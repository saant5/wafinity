# gateway.py
# Render-ready single-service WAFinity demo
# One Flask app only: WAF + SOC Dashboard + Demo Vendor App

from flask import (
    Flask,
    request,
    Response,
    jsonify,
    send_file,
    render_template,
    render_template_string,
    redirect,
    url_for,
)
import json
import os
import time
import io
import urllib.parse
from datetime import datetime, timezone, timedelta

from core.engine import detect
from ml_engine.predictor import predict_smart, add_to_allowlist, update_trust
from ml_engine.train_model import log_feedback
from alerts.alerts import send_block_alert

IST = timezone(timedelta(hours=5, minutes=30))


def ist_now_str():
    return datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")


PROJECT_NAME = "AI-Powered Web Application Firewall with a Real-Time Security Operations Center (SOC) Dashboard"

LOG_DIR = "logs"
LOG_PATH = os.path.join(LOG_DIR, "events.jsonl")

app = Flask(
    __name__,
    template_folder=os.path.join("dashboard", "templates"),
    static_folder=os.path.join("dashboard", "static"),
)

AUTO_BAN_ENABLED = True
AUTO_BAN_THRESHOLD = 5
AUTO_BAN_WINDOW_SEC = 120

BAN_ESCALATION_ENABLED = True
BAN_DURATIONS = [300, 1800, 7200, 86400]
BAN_STRIKE_RESET_SEC = 3600

_ai_hits = {}
_ban_until = {}
_ip_strikes = {}
_last_ban_time = {}

_event_counter = 0

ALL_THREAT_TYPES = [
    "SQL_INJECTION",
    "XSS",
    "COMMAND_INJECTION",
    "PATH_TRAVERSAL",
    "AI_ANOMALY",
    "AUTO_BAN",
]

INTERNAL_PREFIXES = (
    "/dashboard",
    "/api/",
    "/analyze",
    "/event/",
    "/health",
    "/admin/",
    "/shop",
)

STATIC_PREFIXES = (
    "/favicon.ico",
    "/static",
    "/css",
    "/js",
    "/images",
)


# ===============================
# Helpers
# ===============================

def ensure_logs_dir():
    os.makedirs(LOG_DIR, exist_ok=True)


def now():
    return int(time.time())


def get_client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def ban_seconds_left(ip: str) -> int:
    return max(0, int(_ban_until.get(ip, 0) - now()))


def is_ip_banned(ip: str) -> bool:
    until = _ban_until.get(ip, 0)
    if until <= now():
        if ip in _ban_until:
            del _ban_until[ip]
        return False
    return True


def register_ai_hit(ip: str):
    t = now()
    hits = _ai_hits.get(ip, [])
    hits.append(t)

    cutoff = t - AUTO_BAN_WINDOW_SEC
    hits = [x for x in hits if x >= cutoff]
    _ai_hits[ip] = hits

    if len(hits) < AUTO_BAN_THRESHOLD:
        return (False, 0, _ip_strikes.get(ip, 0))

    _ai_hits[ip] = []

    last_ban = _last_ban_time.get(ip, 0)
    if last_ban and (t - last_ban) > BAN_STRIKE_RESET_SEC:
        _ip_strikes[ip] = 0

    strike = _ip_strikes.get(ip, 0) + 1
    _ip_strikes[ip] = strike
    _last_ban_time[ip] = t

    if BAN_ESCALATION_ENABLED:
        idx = min(strike - 1, len(BAN_DURATIONS) - 1)
        ban_for = BAN_DURATIONS[idx]
    else:
        ban_for = 300

    _ban_until[ip] = t + ban_for
    return (True, ban_for, strike)


def build_payload_for_analysis():
    path_qs = request.full_path if request.query_string else request.path
    body = request.get_data(cache=True) or b""
    body_text = body.decode("utf-8", errors="ignore")

    raw_url = urllib.parse.unquote_plus(request.url)
    decoded_path_qs = urllib.parse.unquote_plus(path_qs)

    return f"{request.method} {decoded_path_qs}\n{raw_url}\n{body_text}"


def payload_preview_from_text(payload: str, max_len: int = 300) -> str:
    payload = payload or ""
    return payload[:max_len]


def decode_payload_preview(payload: str) -> str:
    if not payload:
        return ""
    try:
        return urllib.parse.unquote_plus(payload)
    except Exception:
        return payload


def generate_event_id() -> str:
    global _event_counter
    _event_counter += 1
    return f"EVT-{datetime.now(IST).strftime('%Y%m%d-%H%M%S')}-{_event_counter:03d}"


def get_severity(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
            return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def build_reason_text(reason: str, threats: list) -> str:
    if reason == "AUTO_BAN":
        return "This client has been temporarily restricted due to repeated suspicious activity."
    return "The request was identified as unsafe and blocked by the Web Application Firewall."


def normalize_threat_list(threats):
    if not threats:
        return []
    return [str(t).upper() for t in threats if str(t).strip()]


def log_event(event):
    ensure_logs_dir()
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def read_all_events():
    ensure_logs_dir()
    events = []
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    event["threats"] = normalize_threat_list(event.get("threats", []))
                    events.append(event)
                except Exception:
                    pass
    return events


def find_event_by_id(event_id: str):
    if not event_id:
        return None
    events = read_all_events()
    for event in events:
        if str(event.get("event_id", "")) == str(event_id):
            return event
    return None


def matches_filter(event, ftype):
    if not ftype or ftype == "ALL":
        return True
    threats = normalize_threat_list(event.get("threats", []))
    return ftype in threats


def wants_html_response():
    accept = request.headers.get("Accept", "")
    return "text/html" in accept.lower()


def blocked_page_response(event, reason="MALICIOUS_REQUEST", status_code=403):
    event["event_id"] = event.get("event_id") or generate_event_id()
    event["severity"] = event.get("severity") or get_severity(int(event.get("final_score", 0)))
    event["decoded_payload"] = event.get("decoded_payload") or decode_payload_preview(
        event.get("payload_preview", "")
    )
    event["reason_text"] = event.get("reason_text") or build_reason_text(
        reason, event.get("threats", [])
    )

    return (
        render_template(
            "blocked.html",
            event=event,
            reason=reason,
            project_name=PROJECT_NAME,
        ),
        status_code,
    )


# ===============================
# Local Demo Vendor App
# ===============================

def demo_layout(title: str, content: str):
    return render_template_string(
        """
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{ title }}</title>
            <meta name="viewport" content="width=device-width, initial-scale=1" />
            <style>
                body { font-family: Arial, sans-serif; margin: 0; background:#f5f7fb; color:#222; }
                header { background:#111827; color:white; padding:16px 24px; }
                nav a { color:white; margin-right:16px; text-decoration:none; font-weight:600; }
                main { max-width:1000px; margin:30px auto; background:white; padding:24px; border-radius:12px; box-shadow:0 4px 18px rgba(0,0,0,.08); }
                h1 { margin-top:0; }
                .card { background:#f9fafb; border:1px solid #e5e7eb; padding:16px; border-radius:10px; margin:16px 0; }
                input, textarea { width:100%; padding:10px; margin:8px 0 14px; border:1px solid #d1d5db; border-radius:8px; }
                button { background:#2563eb; color:white; border:none; padding:10px 16px; border-radius:8px; cursor:pointer; }
                .muted { color:#6b7280; }
            </style>
        </head>
        <body>
            <header>
                <nav>
                    <a href="/shop">Home</a>
                    <a href="/shop/login">Login</a>
                    <a href="/shop/products">Products</a>
                    <a href="/shop/search">Search</a>
                    <a href="/shop/contact">Contact</a>
                    <a href="/dashboard">SOC Dashboard</a>
                </nav>
            </header>
            <main>
                {{ content|safe }}
            </main>
        </body>
        </html>
        """,
        title=title,
        content=content,
    )


def local_vendor_response(path: str):
    path = (path or "").strip("/")

    if path in ("", "shop"):
        return demo_layout(
            "Vendor Home",
            """
            <h1>Vendor Demo Application</h1>
            <p class="muted">This application is protected by the AI-powered WAF gateway.</p>
            <div class="card">
                <h3>Demo Features</h3>
                <p>Browse products, search inventory, try login, and monitor attacks in the SOC dashboard.</p>
            </div>
            """,
        )

    if path in ("login", "shop/login"):
        return demo_layout(
            "Login",
            """
            <h1>Customer Login</h1>
            <form method="post" action="/shop/login">
                <label>Email</label>
                <input type="text" name="email" placeholder="user@example.com">
                <label>Password</label>
                <input type="password" name="password" placeholder="Enter password">
                <button type="submit">Login</button>
            </form>
            """,
        )

    if path in ("products", "shop/products"):
        return demo_layout(
            "Products",
            """
            <h1>Products</h1>
            <div class="card"><strong>Firewall Appliance</strong><p>Enterprise-grade protection for web traffic.</p></div>
            <div class="card"><strong>SOC Dashboard Suite</strong><p>Monitor threats, blocked requests, and attacker IPs.</p></div>
            <div class="card"><strong>Threat Analytics Pack</strong><p>Visual insights for attack trends and categories.</p></div>
            """,
        )

    if path in ("search", "shop/search"):
        q = request.args.get("q", "")
        return demo_layout(
            "Search",
            f"""
            <h1>Search Products</h1>
            <form method="get" action="/shop/search">
                <label>Keyword</label>
                <input type="text" name="q" value="{q}" placeholder="Search here">
                <button type="submit">Search</button>
            </form>
            <div class="card">
                <strong>Search Query:</strong> {q or "No query entered"}
            </div>
            """,
        )

    if path in ("contact", "shop/contact"):
        return demo_layout(
            "Contact",
            """
            <h1>Contact Us</h1>
            <form method="post" action="/shop/contact">
                <label>Name</label>
                <input type="text" name="name" placeholder="Your name">
                <label>Message</label>
                <textarea name="message" rows="5" placeholder="Type your message"></textarea>
                <button type="submit">Send Message</button>
            </form>
            """,
        )

    return Response("Vendor page not found", status=404)


# ===============================
# Health Route
# ===============================

@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "gateway",
        "mode": "single-service-render",
        "project": PROJECT_NAME,
    }), 200


# ===============================
# Hybrid Analysis
# ===============================

def analyze_payload_text(payload: str):
    payload = payload or ""

    verdict = detect(payload)
    rule_score = int(verdict.get("risk_score", 0))
    rule_malicious = bool(verdict.get("malicious", False))
    threats = normalize_threat_list(verdict.get("threats", []) or [])

    ai_score = 0
    ai_malicious = False

    try:
        if (
            "?" in payload
            or payload.startswith("POST")
            or payload.startswith("PUT")
            or payload.startswith("PATCH")
        ):
            client_ip = get_client_ip()
            ai = predict_smart(payload, ip=client_ip, path=request.path if request else "/")
            ai_malicious = bool(ai.get("blocked", False))
            ai_score = int(float(ai.get("confidence", 0)))
    except Exception as e:
        print(f"[ML ERROR] {e}")

    final_score = max(rule_score, ai_score)
    decision = "BLOCK" if (rule_malicious or ai_malicious) else "ALLOW"

    log_threats = list(threats)
    if ai_malicious and "AI_ANOMALY" not in log_threats:
        log_threats.append("AI_ANOMALY")

    return {
        "rule_score": rule_score,
        "rule_malicious": rule_malicious,
        "ai_score": ai_score,
        "ai_malicious": ai_malicious,
        "final_score": final_score,
        "decision": decision,
        "threats": log_threats,
    }


# ===============================
# Dashboard / Event Routes
# ===============================

@app.get("/dashboard")
def show_dashboard():
    return render_template("dashboard.html", project_name=PROJECT_NAME)


@app.get("/event/<event_id>")
def event_detail(event_id):
    event = find_event_by_id(event_id)
    if not event:
        return Response("Event not found", status=404)

    threats = normalize_threat_list(event.get("threats", []))
    reason = "RULE_ENGINE"

    if "AUTO_BAN" in threats:
        reason = "AUTO_BAN"
    elif "AI_ANOMALY" in threats and len(threats) == 1:
        reason = "AI_ANOMALY"

    event["severity"] = event.get("severity") or get_severity(int(event.get("final_score", 0)))
    event["decoded_payload"] = event.get("decoded_payload") or decode_payload_preview(
        event.get("payload_preview", "")
    )
    event["reason_text"] = event.get("reason_text") or build_reason_text(reason, threats)

    return render_template(
        "blocked.html",
        event=event,
        reason=reason,
        project_name=PROJECT_NAME,
    )


@app.get("/api/search")
def api_search():
    q = (request.args.get("q") or "").strip().lower()
    ip = (request.args.get("ip") or "").strip()
    ttype = (request.args.get("type") or "ALL").strip().upper()
    decision = (request.args.get("decision") or "ALL").strip().upper()

    from_ts = request.args.get("from_ts")
    to_ts = request.args.get("to_ts")
    from_ts = int(from_ts) if from_ts and from_ts.isdigit() else None
    to_ts = int(to_ts) if to_ts and to_ts.isdigit() else None

    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))

    events = read_all_events()

    def match(e):
        if ip and (e.get("ip") != ip):
            return False
        if decision != "ALL" and str(e.get("decision", "")).upper() != decision:
            return False
        threats = normalize_threat_list(e.get("threats") or [])
        if ttype != "ALL" and ttype not in threats:
            return False
        ts = int(e.get("ts") or 0)
        if from_ts is not None and ts < from_ts:
            return False
        if to_ts is not None and ts > to_ts:
            return False
        if q:
            hay = " ".join(
                [
                    str(e.get("event_id", "")),
                    str(e.get("path", "")),
                    str(e.get("query", "")),
                    str(e.get("payload_preview", "")),
                    str(e.get("source", "")),
                    str(e.get("decision", "")),
                    " ".join(threats),
                ]
            ).lower()
            if q not in hay:
                return False
        return True

    matched = [e for e in events if match(e)]
    matched.sort(key=lambda x: int(x.get("ts") or 0), reverse=True)
    total = len(matched)
    sliced = matched[offset: offset + limit]

    return jsonify({"count": total, "logs": sliced})


@app.get("/api/logs")
def api_logs():
    ftype = request.args.get("type", "ALL").upper()
    limit = int(request.args.get("limit", 50))

    events = read_all_events()
    filtered = [e for e in events if matches_filter(e, ftype)]
    filtered.sort(key=lambda x: int(x.get("ts") or 0), reverse=True)

    return jsonify({"logs": filtered[:limit]})


@app.get("/api/export")
def export_filter():
    ftype = request.args.get("type", "ALL").upper()

    events = read_all_events()
    filtered = [e for e in events if matches_filter(e, ftype)]
    filtered.sort(key=lambda x: int(x.get("ts") or 0), reverse=True)

    export_obj = {
        "exported_at": ist_now_str(),
        "filter": ftype,
        "count": len(filtered),
        "logs": filtered,
    }

    buf = io.BytesIO()
    buf.write(json.dumps(export_obj, indent=2).encode("utf-8"))
    buf.seek(0)

    filename = f"soc_filter_export_{ftype}_{datetime.now(IST).strftime('%Y%m%d_%H%M%S')}.json"
    return send_file(buf, mimetype="application/json", as_attachment=True, download_name=filename)


@app.get("/api/export_search")
def export_search():
    q = request.args.get("q", "").strip().lower()
    ftype = request.args.get("type", "ALL").upper()
    decision = request.args.get("decision", "ALL").upper()
    ip = request.args.get("ip", "").strip()

    page_only = request.args.get("page_only", "0") == "1"
    page = int(request.args.get("page", "1"))
    limit = int(request.args.get("limit", "50"))
    offset = (page - 1) * limit

    events = read_all_events()
    filtered = [e for e in events if matches_filter(e, ftype)]

    def event_text(e):
        threats = normalize_threat_list(e.get("threats", []))
        return (
            f"{e.get('event_id','')} "
            f"{e.get('payload_preview','')} "
            f"{e.get('path','')} "
            f"{e.get('decision','')} "
            f"{e.get('ip','')} "
            f"{e.get('source','')} "
            f"{' '.join(threats)}"
        ).lower()

    if q:
        filtered = [e for e in filtered if q in event_text(e)]
    if decision != "ALL":
        filtered = [e for e in filtered if str(e.get("decision", "")).upper() == decision]
    if ip:
        filtered = [e for e in filtered if str(e.get("ip", "")) == ip]

    filtered.sort(key=lambda x: int(x.get("ts") or 0), reverse=True)
    export_logs = filtered[offset: offset + limit] if page_only else filtered

    export_obj = {
        "exported_at": ist_now_str(),
        "filters": {
            "q": q, "type": ftype, "decision": decision, "ip": ip,
            "page_only": page_only, "page": page, "limit": limit,
        },
        "count": len(export_logs),
        "logs": export_logs,
    }

    buf = io.BytesIO()
    buf.write(json.dumps(export_obj, indent=2).encode("utf-8"))
    buf.seek(0)

    filename = f"soc_export_{datetime.now(IST).strftime('%Y%m%d_%H%M%S')}.json"
    return send_file(buf, mimetype="application/json", as_attachment=True, download_name=filename)


@app.post("/api/clear_logs")
def clear_logs():
    try:
        ensure_logs_dir()
        with open(LOG_PATH, "w", encoding="utf-8") as f:
            f.write("")
        return jsonify({"success": True, "message": "Logs cleared successfully"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.get("/api/summary")
def api_summary():
    ftype = request.args.get("type", "ALL").upper()
    now_ts = now()
    window_sec = 5 * 60
    bucket_sec = 60

    events = read_all_events()
    filtered = [e for e in events if matches_filter(e, ftype)]

    total = len(filtered)
    blocked = sum(1 for e in filtered if str(e.get("decision", "")).upper() == "BLOCK")
    allowed = sum(1 for e in filtered if str(e.get("decision", "")).upper() == "ALLOW")

    type_counts = {threat: 0 for threat in ALL_THREAT_TYPES}
    for e in filtered:
        threats = normalize_threat_list(e.get("threats", []))
        for t in threats:
            if t not in type_counts:
                type_counts[t] = 0
            type_counts[t] += 1

    ip_counts = {}
    for e in filtered:
        if str(e.get("decision", "")).upper() != "BLOCK":
            continue
        ip = str(e.get("ip", "unknown"))
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

    top_ips = [
        {"ip": ip, "count": count}
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:8]
    ]

    start_ts = now_ts - window_sec + 1
    aligned_start = start_ts - (start_ts % bucket_sec)

    labels = []
    counts = []
    bucket_map = {}

    for t in range(aligned_start, now_ts + 1, bucket_sec):
        ist_time = datetime.fromtimestamp(t, tz=IST)
        labels.append(ist_time.strftime("%H:%M"))
        bucket_map[t] = 0

    for e in filtered:
        if str(e.get("decision", "")).upper() != "BLOCK":
            continue
        ts = int(e.get("ts", 0))
        if ts < aligned_start or ts > now_ts:
            continue
        bucket_key = ts - (ts % bucket_sec)
        if bucket_key in bucket_map:
            bucket_map[bucket_key] += 1

    for t in range(aligned_start, now_ts + 1, bucket_sec):
        counts.append(bucket_map.get(t, 0))

    return jsonify({
        "filter": ftype,
        "total": total,
        "blocked": blocked,
        "allowed": allowed,
        "type_counts": type_counts,
        "top_ips": top_ips,
        "trend": {"labels": labels, "counts": counts},
    })


# ===============================
# Attack Simulator API
# ===============================

@app.post("/analyze")
def analyze():
    data = request.get_json(silent=True) or {}

    payload = str(data.get("payload", ""))
    source = str(data.get("source", "attack_app"))
    attack_name = str(data.get("attack_name", "CUSTOM"))
    client_ip = str(data.get("ip", get_client_ip()))

    if AUTO_BAN_ENABLED and is_ip_banned(client_ip):
        event = {
            "event_id": generate_event_id(),
            "ts": now(),
            "time": ist_now_str(),
            "ip": client_ip,
            "source": source,
            "method": "POST",
            "path": "/analyze",
            "query": "",
            "decision": "BLOCK",
            "threats": ["AUTO_BAN"],
            "risk_score": 100,
            "ai_score": 100,
            "final_score": 100,
            "severity": "CRITICAL",
            "payload_preview": payload_preview_from_text(payload),
            "decoded_payload": decode_payload_preview(payload_preview_from_text(payload)),
            "attack_name": attack_name,
            "banned_now": False,
            "ban_for": 0,
            "strike": _ip_strikes.get(client_ip, 0),
            "ban_until": _ban_until.get(client_ip),
            "ban_seconds_left": ban_seconds_left(client_ip),
        }
        log_event(event)
        send_block_alert(event)

        if wants_html_response():
            return blocked_page_response(event, reason="AUTO_BAN", status_code=403)

        return jsonify({
            "success": True,
            "blocked": True,
            "reason": "AUTO_BAN",
            "strike": _ip_strikes.get(client_ip, 0),
            "ban_until": _ban_until.get(client_ip),
            "ban_seconds_left": ban_seconds_left(client_ip),
        }), 403

    result = analyze_payload_text(payload)

    banned_now = False
    ban_for = 0
    strike = _ip_strikes.get(client_ip, 0)

    if AUTO_BAN_ENABLED and result["ai_malicious"]:
        banned_now, ban_for, strike = register_ai_hit(client_ip)

    event = {
        "event_id": generate_event_id(),
        "ts": now(),
        "time": ist_now_str(),
        "ip": client_ip,
        "source": source,
        "method": "POST",
        "path": "/analyze",
        "query": "",
        "decision": result["decision"],
        "threats": result["threats"],
        "risk_score": result["rule_score"],
        "ai_score": result["ai_score"],
        "final_score": result["final_score"],
        "severity": get_severity(result["final_score"]),
        "payload_preview": payload_preview_from_text(payload),
        "decoded_payload": decode_payload_preview(payload_preview_from_text(payload)),
        "attack_name": attack_name,
        "banned_now": banned_now,
        "ban_for": ban_for,
        "strike": strike,
        "ban_until": _ban_until.get(client_ip),
        "ban_seconds_left": ban_seconds_left(client_ip),
    }
    log_event(event)

    if result["decision"] == "BLOCK":
        send_block_alert(event)

    status = 403 if result["decision"] == "BLOCK" else 200

    if result["decision"] == "BLOCK" and wants_html_response():
        return blocked_page_response(
            event,
            reason="RULE_ENGINE" if result["rule_malicious"] else "AI_ANOMALY",
            status_code=403,
        )

    return jsonify({
        "success": True,
        "blocked": result["decision"] == "BLOCK",
        "decision": result["decision"],
        "threats": result["threats"],
        "rule_score": result["rule_score"],
        "ai_score": result["ai_score"],
        "final_score": result["final_score"],
        "severity": get_severity(result["final_score"]),
        "ai_malicious": result["ai_malicious"],
        "banned_now": banned_now,
        "ban_for": ban_for,
        "strike": strike,
        "ban_until": _ban_until.get(client_ip),
        "ban_seconds_left": ban_seconds_left(client_ip),
    }), status


# ===============================
# Local Vendor Routes
# ===============================

@app.get("/")
def root_redirect():
    return redirect(url_for("shop_home"))


@app.route("/shop", methods=["GET"])
def shop_home():
    return local_vendor_response("")


@app.route("/shop/login", methods=["GET", "POST"])
def shop_login():
    if request.method == "POST":
        email = request.form.get("email", "")
        return demo_layout(
            "Login Result",
            f"""
            <h1>Login Attempt</h1>
            <div class="card">
                <strong>Email:</strong> {email or "No email provided"}<br>
                <span class="muted">This is a demo vendor login protected by the WAF.</span>
            </div>
            """,
        )
    return local_vendor_response("login")


@app.route("/shop/products", methods=["GET"])
def shop_products():
    return local_vendor_response("products")


@app.route("/shop/search", methods=["GET"])
def shop_search():
    return local_vendor_response("search")


@app.route("/shop/contact", methods=["GET", "POST"])
def shop_contact():
    if request.method == "POST":
        name = request.form.get("name", "")
        return demo_layout(
            "Contact Submitted",
            f"""
            <h1>Message Received</h1>
            <div class="card">
                Thank you, {name or "Guest"}. Your message was submitted successfully.
            </div>
            """,
        )
    return local_vendor_response("contact")


# ===============================
# Protected Catch-all WAF Layer
# ===============================

@app.route("/vendor/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def protected_vendor(path):
    client_ip = get_client_ip()
    payload = build_payload_for_analysis()

    if AUTO_BAN_ENABLED and is_ip_banned(client_ip):
        event = {
            "event_id": generate_event_id(),
            "ts": now(),
            "time": ist_now_str(),
            "ip": client_ip,
            "source": "proxy",
            "method": request.method,
            "path": request.path,
            "query": request.query_string.decode("utf-8", errors="ignore"),
            "decision": "BLOCK",
            "threats": ["AUTO_BAN"],
            "risk_score": 100,
            "ai_score": 100,
            "final_score": 100,
            "severity": "CRITICAL",
            "payload_preview": payload_preview_from_text(payload),
            "decoded_payload": decode_payload_preview(payload_preview_from_text(payload)),
            "banned_now": False,
            "ban_for": 0,
            "strike": _ip_strikes.get(client_ip, 0),
            "ban_until": _ban_until.get(client_ip),
            "ban_seconds_left": ban_seconds_left(client_ip),
        }
        log_event(event)
        send_block_alert(event)
        return blocked_page_response(event, reason="AUTO_BAN", status_code=403)

    result = analyze_payload_text(payload)

    banned_now = False
    ban_for = 0
    strike = _ip_strikes.get(client_ip, 0)

    if AUTO_BAN_ENABLED and result["ai_malicious"]:
        banned_now, ban_for, strike = register_ai_hit(client_ip)

    event = {
        "event_id": generate_event_id(),
        "ts": now(),
        "time": ist_now_str(),
        "ip": client_ip,
        "source": "proxy",
        "method": request.method,
        "path": request.path,
        "query": request.query_string.decode("utf-8", errors="ignore"),
        "decision": result["decision"],
        "threats": result["threats"],
        "risk_score": result["rule_score"],
        "ai_score": result["ai_score"],
        "final_score": result["final_score"],
        "severity": get_severity(result["final_score"]),
        "payload_preview": payload_preview_from_text(payload),
        "decoded_payload": decode_payload_preview(payload_preview_from_text(payload)),
        "banned_now": banned_now,
        "ban_for": ban_for,
        "strike": strike,
        "ban_until": _ban_until.get(client_ip),
        "ban_seconds_left": ban_seconds_left(client_ip),
    }
    log_event(event)

    if result["decision"] == "BLOCK":
        send_block_alert(event)
        return blocked_page_response(
            event,
            reason="RULE_ENGINE" if result["rule_malicious"] else "AI_ANOMALY",
            status_code=403,
        )

    return local_vendor_response(path)


# ===============================
# Admin Routes
# ===============================

@app.post("/admin/feedback")
def admin_feedback():
    data = request.get_json(silent=True) or {}
    payload = str(data.get("payload", ""))
    true_label = int(data.get("true_label", 0))
    ip = str(data.get("ip", ""))

    log_feedback(payload, true_label)

    if ip:
        was_false_positive = (true_label == 0)
        update_trust(ip, was_false_positive)

    return jsonify({"success": True, "message": "Feedback logged. Model will auto-retrain after 500 entries."}), 200


@app.post("/admin/allowlist")
def admin_allowlist():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    path = data.get("path")

    add_to_allowlist(ip=ip, path=path)
    return jsonify({"success": True, "message": "Allowlist updated."}), 200


ensure_logs_dir()

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)