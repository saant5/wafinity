import joblib
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
import json
import os

MODEL_PATH = Path(__file__).resolve().parent / "waf_model.pkl"
_model = None

# ─── Original load_model (unchanged) ──────────────────────────────────────────
def load_model():
    global _model
    if _model is None:
        _model = joblib.load(MODEL_PATH)
    return _model


# ─── Original predict_payload (unchanged) ─────────────────────────────────────
def predict_payload(payload: str):
    model = load_model()
    payload = payload or ""

    prediction = model.predict([payload])[0]

    if hasattr(model, "predict_proba"):
        prob = model.predict_proba([payload])[0][1]
    else:
        prob = 1.0 if prediction == 1 else 0.0

    return {
        "is_malicious": bool(prediction),
        "confidence": round(prob * 100, 2)
    }


# ─── NEW: False Positive Reducer ──────────────────────────────────────────────
# Drop-in wrapper around predict_payload.
# Call predict_smart() instead of predict_payload() in gateway.py.

DATA_DIR        = Path(__file__).resolve().parent.parent / "data"
ALLOWLIST_PATH  = DATA_DIR / "allowlist.json"
TRUST_PATH      = DATA_DIR / "trust_scores.json"

# Only block if confidence >= this threshold (reduces false positives)
BLOCK_THRESHOLD = 75.0

# In-memory session tracker  {ip: [(datetime, is_malicious), ...]}
_session_history = defaultdict(list)


def _load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default

def _save_json(path, data):
    os.makedirs(path.parent, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def add_to_allowlist(ip: str = None, path: str = None):
    """Add a trusted IP or path to the allowlist."""
    al = _load_json(ALLOWLIST_PATH, {"ips": [], "paths": []})
    if ip and ip not in al["ips"]:
        al["ips"].append(ip)
    if path and path not in al["paths"]:
        al["paths"].append(path)
    _save_json(ALLOWLIST_PATH, al)


def update_trust(ip: str, was_false_positive: bool):
    """Call this when admin corrects a wrong block decision."""
    scores = _load_json(TRUST_PATH, {})
    score = scores.get(ip, 50)
    score = min(100, score + 5) if was_false_positive else max(0, score - 10)
    scores[ip] = score
    _save_json(TRUST_PATH, scores)


def predict_smart(payload: str, ip: str = "unknown", path: str = "/"):
    """
    Upgraded predict — wraps original predict_payload with:
    1. Allowlist check        → instant allow
    2. Trust score adjustment → reduces confidence for known-good IPs
    3. Session analysis       → escalates repeated attackers
    4. Confidence threshold   → only block if confident enough

    Returns same shape as predict_payload() plus extra fields.
    """
    # 1. Allowlist check
    al = _load_json(ALLOWLIST_PATH, {"ips": [], "paths": []})
    if ip in al["ips"] or any(path.startswith(p) for p in al["paths"]):
        return {
            "is_malicious": False,
            "confidence": 0.0,
            "reason": "allowlisted",
            "blocked": False,
        }

    # 2. Base prediction (your original function)
    result = predict_payload(payload)
    confidence = result["confidence"]

    # 3. Trust score adjustment
    scores = _load_json(TRUST_PATH, {})
    trust = scores.get(ip, 50)
    # High trust slightly lowers effective confidence
    adjusted_conf = confidence * (1 - trust / 200)

    # 4. Session behavior: if this IP is repeatedly sending attacks, escalate
    now = datetime.utcnow()
    history = _session_history[ip]
    history = [(t, m) for t, m in history if now - t < timedelta(minutes=5)]
    history.append((now, result["is_malicious"]))
    _session_history[ip] = history

    attack_ratio = sum(1 for _, m in history if m) / len(history)
    if attack_ratio > 0.6:
        adjusted_conf = min(100, adjusted_conf * 1.2)

    # 5. Threshold decision
    blocked = result["is_malicious"] and adjusted_conf >= BLOCK_THRESHOLD

    return {
        "is_malicious": result["is_malicious"],
        "confidence":   round(adjusted_conf, 2),
        "blocked":      blocked,
        "trust_score":  trust,
        "reason":       "ml_detection" if blocked else (
                        "low_confidence" if result["is_malicious"] else "benign"
                        ),
    }