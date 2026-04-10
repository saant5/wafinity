from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, render_template, request, send_file

# Project root = WAFinity_Enterprise/
BASE_DIR = Path(__file__).resolve().parents[1]

# Ensure Flask loads templates from dashboard/templates
app = Flask(__name__, template_folder=str(Path(__file__).resolve().parent / "templates"))

# Log file (JSON Lines)
LOG_FILE = BASE_DIR / "logs" / "waf_logs.jsonl"

# Dashboard window (trend) = last 5 minutes
WINDOW_SECONDS = 5 * 60
BUCKET_SECONDS = 10  # for line chart buckets


def _safe_upper(s: str) -> str:
    return (s or "").strip().upper()


def read_logs(limit: int = 20000) -> List[Dict[str, Any]]:
    """
    Reads last N JSONL lines.
    Returns latest-first list.
    """
    logs: List[Dict[str, Any]] = []
    try:
        if LOG_FILE.exists():
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                lines = f.readlines()
            for line in lines[-limit:]:
                line = line.strip()
                if not line:
                    continue
                try:
                    logs.append(json.loads(line))
                except:
                    pass
        return logs[::-1]  # latest first
    except:
        return []


def get_threats(log: Dict[str, Any]) -> List[str]:
    """
    Support both new 'threats' and old 'attacks' fields.
    Ensure normalized uppercase names.
    """
    items = log.get("threats", log.get("attacks", [])) or []
    out = []
    for x in items:
        if not x:
            continue
        out.append(_safe_upper(str(x)))
    return out


def get_ip(log: Dict[str, Any]) -> str:
    return str(log.get("ip") or log.get("client_ip") or "unknown")


def get_ts(log: Dict[str, Any]) -> float:
    """
    Accept ts formats:
      - 'ts' as epoch seconds (float/int)
      - 'timestamp' as epoch seconds
      - if missing => now
    """
    ts = log.get("ts", log.get("timestamp", None))
    if ts is None:
        return time.time()
    try:
        return float(ts)
    except:
        return time.time()


def apply_filter(logs: List[Dict[str, Any]], threat_filter: Optional[str]) -> List[Dict[str, Any]]:
    """
    Filter logs by threat type:
      threat_filter None => ALL
      threat_filter = 'SQL_INJECTION'/'XSS'/'COMMAND_INJECTION'
    """
    if not threat_filter:
        return logs
    filtered = []
    for l in logs:
        threats = get_threats(l)
        if threat_filter in threats:
            filtered.append(l)
    return filtered


def build_type_counts(logs: List[Dict[str, Any]]) -> Dict[str, int]:
    c: Counter = Counter()
    for l in logs:
        for th in get_threats(l):
            c[th] += 1
    return dict(c)


def build_top_ips(logs: List[Dict[str, Any]], limit: int = 5) -> List[Dict[str, Any]]:
    c: Counter = Counter()
    for l in logs:
        # count only malicious (has threats)
        if get_threats(l):
            c[get_ip(l)] += 1
    return [{"ip": ip, "count": cnt} for ip, cnt in c.most_common(limit)]


def build_trend_series(logs: List[Dict[str, Any]]) -> Dict[str, List[Any]]:
    """
    Line chart for last 5 minutes.
    Buckets every 10 seconds.
    """
    now = int(time.time())
    start = now - WINDOW_SECONDS

    # build empty buckets
    buckets = list(range(start - (start % BUCKET_SECONDS), now + 1, BUCKET_SECONDS))
    counts = {b: 0 for b in buckets}

    for l in logs:
        ts = int(get_ts(l))
        if ts < start:
            continue
        b = ts - (ts % BUCKET_SECONDS)
        if b in counts:
            # count only malicious (has threats)
            if get_threats(l):
                counts[b] += 1

    labels = [time.strftime("%H:%M:%S", time.localtime(b)) for b in buckets]
    values = [counts[b] for b in buckets]
    return {"labels": labels, "counts": values}


@app.route("/")
def index():
    # helpful debug
    print("Dashboard BASE_DIR:", BASE_DIR)
    print("Reading logs from:", LOG_FILE)
    print("Log file exists:", LOG_FILE.exists())
    return render_template("index.html")


@app.route("/api/logs")
def api_logs():
    """
    Latest events (optionally filtered).
    Query: ?type=ALL|SQL_INJECTION|XSS|COMMAND_INJECTION&limit=200
    """
    threat_filter = _safe_upper(request.args.get("type", "ALL"))
    if threat_filter == "ALL":
        threat_filter = None

    limit = int(request.args.get("limit", "200"))
    logs = read_logs(limit=20000)
    logs = apply_filter(logs, threat_filter)[:limit]
    return jsonify({"filter": threat_filter or "ALL", "logs": logs})


@app.route("/api/summary")
def api_summary():
    """
    Single endpoint for dashboard:
    - total, blocked, allowed
    - type_counts (bar chart)
    - trend (line chart)
    - top_ips
    Query: ?type=ALL|SQL_INJECTION|XSS|COMMAND_INJECTION
    """
    threat_filter = _safe_upper(request.args.get("type", "ALL"))
    if threat_filter == "ALL":
        threat_filter = None

    logs = read_logs(limit=20000)
    logs_f = apply_filter(logs, threat_filter)

    total = len(logs_f)
    blocked = sum(1 for l in logs_f if _safe_upper(str(l.get("decision", ""))) == "BLOCK")
    allowed = sum(1 for l in logs_f if _safe_upper(str(l.get("decision", ""))) == "ALLOW")

    return jsonify({
        "filter": threat_filter or "ALL",
        "total": total,
        "blocked": blocked,
        "allowed": allowed,
        "type_counts": build_type_counts(logs_f),
        "trend": build_trend_series(logs_f),
        "top_ips": build_top_ips(logs_f, limit=5),
    })


@app.route("/api/attack_chart")
def api_attack_chart():
    """
    Backward compatible endpoint: returns type counts.
    Supports filter ?type=...
    """
    threat_filter = _safe_upper(request.args.get("type", "ALL"))
    if threat_filter == "ALL":
        threat_filter = None

    logs = read_logs(limit=20000)
    logs_f = apply_filter(logs, threat_filter)
    return jsonify(build_type_counts(logs_f))


@app.route("/api/export")
def api_export():
    """
    Export JSON report for current filter.
    Downloaded file name: wafinity_report.json
    """
    threat_filter = _safe_upper(request.args.get("type", "ALL"))
    if threat_filter == "ALL":
        threat_filter = None

    logs = read_logs(limit=20000)
    logs_f = apply_filter(logs, threat_filter)

    report = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "window_seconds": WINDOW_SECONDS,
        "filter": threat_filter or "ALL",
        "total_events": len(logs_f),
        "type_counts": build_type_counts(logs_f),
        "top_ips": build_top_ips(logs_f, limit=10),
        "events": logs_f[:2000],  # export cap to avoid huge files
    }

    out_path = BASE_DIR / "reports" / "wafinity_report.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    return send_file(str(out_path), as_attachment=True, download_name="wafinity_report.json")


if __name__ == "__main__":
    # keep port configurable, but default 5000 (your current)
    app.run(host="127.0.0.1", port=5000, debug=True)