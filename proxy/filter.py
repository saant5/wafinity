import re
import urllib.parse
import json
import time
from datetime import datetime
from pathlib import Path

from risk_engine.scorer import calculate_risk
from ml_engine.model import ml_anomaly_score
from threat_intel.ip_reputation import check_ip

# -------------------------------
# Normalizer (REAL decoding)
# -------------------------------
def normalize(data: str) -> str:
    if not data:
        return ""
    data = urllib.parse.unquote_plus(data)   # decode %xx and +
    data = data.lower()
    data = re.sub(r"\s+", " ", data)         # normalize spaces
    return data.strip()

# -------------------------------
# Logging Function (JSON Lines)
# -------------------------------
BASE_DIR = Path(__file__).resolve().parents[1]
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ✅ dashboard expects jsonl file
LOG_FILE = LOG_DIR / "waf_logs.jsonl"

def log_attack(result, raw_data, ip, extra=None):
    extra = extra or {}
    now_ts = time.time()

    # ✅ Dashboard-friendly fields + backward compatible fields
    log_entry = {
        "ts": now_ts,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,

        # decision + scores
        "decision": result.get("decision"),
        "risk_score": result.get("score"),   # new name
        "score": result.get("score"),        # old name kept

        # threats + attacks
        "threats": result.get("attacks", []),  # new name
        "attacks": result.get("attacks", []),  # old name kept

        # payload preview
        "payload_preview": raw_data[:300],
        "payload": raw_data[:300],  # old name kept
    }

    # add any optional info like method/path/fingerprint if proxy passes it later
    log_entry.update(extra)

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
    except:
        pass

# -------------------------------
# Attack Signatures (ENTERPRISE)
# -------------------------------
ATTACK_SIGNATURES = {
    "SQL_INJECTION": [
        r"('|%27)\s*or\s*('|%27)?\d+('|%27)?\s*=\s*('|%27)?\d+",
        r"or\s+1\s*=\s*1",
        r"union\s+select",
        r"select\s+.*\s+from",
        r"insert\s+into",
        r"drop\s+table",
        r"--",
        r"#"
    ],
    "XSS": [
        r"<script.*?>",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"<img.*?onerror",
        r"<svg.*?onload"
    ],
    "LFI": [
        r"\.\./",
        r"/etc/passwd",
        r"boot.ini",
        r"/proc/self/environ"
    ],
    "RCE": [
        r"(\||;|&)\s*(ls|cat|whoami|id|pwd|uname|rm|wget|curl|bash|sh)",
    ]
}

REAL_ATTACKS = {"SQL_INJECTION", "XSS", "LFI", "RCE"}

# -------------------------------
# Core Inspection Engine
# -------------------------------
def inspect_request(data, ip):
    print("🔥 INSPECT_REQUEST CALLED")
    raw_data = data or ""
    data = normalize(data or "")

    detected = []
    base_score = 0
    

    # ---------------- Signature Detection ----------------
    for attack, patterns in ATTACK_SIGNATURES.items():
        for p in patterns:
            if re.search(p, data, re.IGNORECASE):
                if attack not in detected:
                    detected.append(attack)
                    base_score += 30  # signature hit weight

    # ---------------- IP Reputation ----------------
    ip_score = 0
    try:
        ip_score = check_ip(ip)  # should return int
        if isinstance(ip_score, int):
            base_score += ip_score
        else:
            ip_score = 0
    except:
        ip_score = 0

    # ---------------- ML Anomaly ----------------
    ml_score = 0.0

    try:
        ml_score = ml_anomaly_score(data)
        if isinstance(ml_score, (int, float)):
           ml_score = float(ml_score)
        else:
          ml_score = 0.0
    except:
        ml_score = 0.0

    has_real_attack = any(a in REAL_ATTACKS for a in detected)

# Controlled anomaly addition (do not block normal traffic)
    if ml_score >= 0.90 and not has_real_attack:
      detected.append("ANOMALY")
      base_score += 10

    # ---------------- Heuristic Anomaly ----------------
    # keep it low weight; don't explode score for long payloads
    anomaly_score = min(len(data) // 800, 5)
    base_score += anomaly_score * 2

    # ---------------- Risk Engine ----------------
    # calculate_risk might be adding big numbers; we clamp later
    try:
        risk_part = calculate_risk(detected, anomaly_score)
        if not isinstance(risk_part, (int, float)):
            risk_part = 0
    except:
        risk_part = 0

    total_score = float(risk_part) + float(base_score)

    # ✅ Clamp score to 0–100 (enterprise dashboard friendly)
    total_score = max(0.0, min(total_score, 100.0))

    # ---------------- Decision Engine (FIXED) ----------------
    has_real_attack = any(a in REAL_ATTACKS for a in detected)
    only_anomaly = (len(detected) == 1 and detected[0] == "ANOMALY")

    # ✅ Block if real signatures match
    if has_real_attack:
        decision = "BLOCK"

    # ✅ Do NOT block ONLY anomaly unless score is truly high
    elif only_anomaly:
        decision = "BLOCK" if total_score >= 90 else "ALLOW"

    # ✅ Mixed: anomaly + other suspicious signals
    elif "ANOMALY" in detected and total_score >= 85:
        decision = "BLOCK"

    # ✅ high risk overall
    elif total_score >= 95:
        decision = "BLOCK"

    else:
        decision = "ALLOW"

    result = {
        "decision": decision,
        "score": int(total_score),
        "attacks": detected
    }

    # ---------------- Logging ----------------
    log_attack(
        result,
        raw_data,
        ip,
        extra={
            "ml_score": ml_score,
            "ip_score": ip_score,
            "heuristic_anomaly": anomaly_score,
        }
        
        )
         
    print("DEBUG → detected:", detected)
    print("DEBUG → base_score:", base_score)
    print("DEBUG → risk_part:", risk_part)
    print("DEBUG → total_score:", total_score)
    
    

    return result