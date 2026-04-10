from __future__ import annotations
import proxy.filter
print("Using filter file:", proxy.filter.__file__)
import json
import time
from pathlib import Path
from typing import Dict, Any
from proxy.ban_manager import is_banned, record_block, escalate_ban, ban_level_text
from proxy.jwt_auth import verify_bearer
from proxy.user_rate_limiter import allow_user


import requests
from flask import Flask, request, Response

# ==============================
# OPTIONAL MODULES (safe imports)
# ==============================
try:
    from proxy.rate_limiter import rate_limit
except Exception:
    rate_limit = None

try:
    from proxy.bot_detector import is_bot
except Exception:
    is_bot = None

try:
    from proxy.fingerprint import fingerprint
except Exception:
    fingerprint = None

# Your WAF inspection logic
# inspect_request(payload, client_ip) -> {"decision": "ALLOW/BLOCK", "attacks":[...], "score": int}
from proxy.filter import inspect_request  # keep this as you already have

app = Flask(__name__)

# ==============================
# CONFIG
# ==============================

# ✅ Change this to your protected app when you want local:
# TARGET_SERVER = "http://127.0.0.1:5001"
TARGET_SERVER = "http://127.0.0.1:5002"
PROXY_PORT = 8080

# ✅ Log file for Dashboard
BASE_DIR = Path(__file__).resolve().parents[1]
LOG_FILE = BASE_DIR / "logs" / "waf_logs.jsonl"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

print(f"🛡️ WAFinity Proxy WAF running on http://127.0.0.1:{PROXY_PORT}")
print(f"➡️ Forwarding to: {TARGET_SERVER}")
print(f"📝 Logging to: {LOG_FILE}")


# ==============================
# Helper Functions
# ==============================

def get_client_ip() -> str:
    # Real IP detection (proxy-safe)
    xf = request.headers.get("X-Forwarded-For")
    if xf:
        return xf.split(",")[0].strip()
    xr = request.headers.get("X-Real-IP")
    if xr:
        return xr.strip()
    return request.remote_addr or "0.0.0.0"


def build_payload() -> str:
    payload_parts = []

    # path + query
    payload_parts.append(request.path or "/")
    if request.query_string:
        payload_parts.append("?" + request.query_string.decode(errors="ignore"))

    # headers
    for k, v in request.headers.items():
        payload_parts.append(f"{k}:{v}")

    # body (limit to avoid huge memory)
    raw = request.get_data()
    if raw:
        try:
            payload_parts.append(raw.decode(errors="ignore")[:2000])
        except Exception:
            pass

    return "\n".join(payload_parts)


def log_event(event: Dict[str, Any]) -> None:
    """Append JSONL line for dashboard."""
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def block_response(result: Dict[str, Any], reason: str = "Threat detected") -> Response:
    attacks = result.get("attacks", [])
    score = result.get("score", 0)
    return Response(
        f"🚫 WAFinity BLOCKED\nReason: {reason}\nAttacks: {attacks}\nRisk Score: {score}\n",
        status=403,
        mimetype="text/plain",
    )


# ==============================
# Reverse Proxy Core
# ==============================

@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def proxy(path: str):
    client_ip = get_client_ip()

    # =========================
    # 1️⃣ BAN CHECK
    # =========================
    banned, remaining = is_banned(client_ip)
    if banned:
        ban_msg = "PERMANENT" if remaining is None else f"{remaining}s remaining"

        ev = {
            "ts": time.time(),
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ip": client_ip,
            "method": request.method,
            "path": "/" + path,
            "decision": "BLOCK",
            "risk_score": 100,
            "threats": ["IP_BANNED"],
            "payload_preview": (request.full_path or "")[:300],
            "ban_remaining": remaining,
            "ban_level": "PERMANENT" if remaining is None else "ACTIVE",
        }
        log_event(ev)
        return Response(f"🚫 BLOCKED: IP BANNED ({ban_msg})", status=403)

    # =========================
    # 2️⃣ API GATEWAY MODE (JWT + RBAC + USER LIMIT)
    # =========================
    PUBLIC_PATHS = {"/", "/api/public", "/auth/login"}
    req_path = "/" + path if path else "/"

    user_id = "anonymous"
    role = "guest"

    if req_path not in PUBLIC_PATHS:
        ok, claims, err = verify_bearer(request.headers.get("Authorization", ""))
        if not ok:
            ev = {
                "ts": time.time(),
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "ip": client_ip,
                "method": request.method,
                "path": req_path,
                "decision": "BLOCK",
                "risk_score": 80,
                "threats": ["AUTH_FAILED"],
                "payload_preview": (request.full_path or "")[:300],
                "auth_error": err,
            }
            log_event(ev)
            return Response(f"🚫 BLOCKED: {err}", status=401)

        user_id = str(claims.get("sub", "unknown"))
        role = str(claims.get("role", "user")).lower()

        # RBAC check
        if req_path.startswith("/api/admin") and role != "admin":
            ev = {
                "ts": time.time(),
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "ip": client_ip,
                "method": request.method,
                "path": req_path,
                "decision": "BLOCK",
                "risk_score": 80,
                "threats": ["RBAC_DENY"],
                "payload_preview": (request.full_path or "")[:300],
                "user": user_id,
                "role": role,
            }
            log_event(ev)
            return Response("🚫 BLOCKED: Admin role required", status=403)

        # Per-user rate limit
        if not allow_user(user_id):
            ev = {
                "ts": time.time(),
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "ip": client_ip,
                "method": request.method,
                "path": req_path,
                "decision": "BLOCK",
                "risk_score": 70,
                "threats": ["USER_RATE_LIMIT"],
                "payload_preview": (request.full_path or "")[:300],
                "user": user_id,
                "role": role,
            }
            log_event(ev)
            return Response("🚫 BLOCKED: User rate limit exceeded", status=429)

    # =========================
    # 3️⃣ OPTIONAL BOT + RATE LIMIT
    # =========================
    ua = request.headers.get("User-Agent", "")
    if is_bot is not None and is_bot(ua):
        record_block(client_ip)
        info = escalate_ban(client_ip)

        ev = {
            "ts": time.time(),
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ip": client_ip,
            "method": request.method,
            "path": "/" + path,
            "decision": "BLOCK",
            "risk_score": 60,
            "threats": ["BOT_DETECTED"],
            "ban_level": ban_level_text(info),
        }
        log_event(ev)
        return Response("🚫 BLOCKED: Bot detected", status=403)

    if rate_limit is not None:
        if not rate_limit(client_ip):
            record_block(client_ip)
            info = escalate_ban(client_ip)

            ev = {
                "ts": time.time(),
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "ip": client_ip,
                "method": request.method,
                "path": "/" + path,
                "decision": "BLOCK",
                "risk_score": 70,
                "threats": ["RATE_LIMIT"],
                "ban_level": ban_level_text(info),
            }
            log_event(ev)
            return Response("🚫 BLOCKED: Rate limit exceeded", status=429)

    # =========================
    # 4️⃣ WAF INSPECTION
    # =========================
    payload = build_payload()
    result = inspect_request(payload, client_ip)

    decision = result.get("decision", "ALLOW").upper()
    attacks = result.get("attacks", []) or []
    score = int(result.get("score", 0) or 0)

    if decision == "BLOCK":
        record_block(client_ip)
        info = escalate_ban(client_ip)

        ev = {
            "ts": time.time(),
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ip": client_ip,
            "method": request.method,
            "path": "/" + path,
            "decision": "BLOCK",
            "risk_score": score,
            "threats": attacks,
            "ban_level": ban_level_text(info),
            "user": user_id,
            "role": role,
        }
        log_event(ev)

        return block_response(result)

    # =========================
    # 5️⃣ FORWARD TO BACKEND
    # =========================
    upstream_url = f"{TARGET_SERVER}/{path}"
    if request.query_string:
        upstream_url += "?" + request.query_string.decode(errors="ignore")

    try:
        headers = dict(request.headers)
        headers.pop("Host", None)
        headers.pop("Content-Length", None)

        # Inject identity headers
        headers["X-User"] = user_id
        headers["X-Role"] = role

        resp = requests.request(
            method=request.method,
            url=upstream_url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=10,
        )

        excluded_headers = {"content-encoding", "content-length", "transfer-encoding", "connection"}
        response_headers = [
            (name, value)
            for (name, value) in resp.headers.items()
            if name.lower() not in excluded_headers
        ]

        return Response(resp.content, resp.status_code, response_headers)

    except Exception as e:
        print("🔥 Proxy Error:", e)
        return Response("Backend server unreachable", status=502)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=PROXY_PORT, debug=True)