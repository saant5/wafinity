import json
from datetime import datetime
from pathlib import Path

LOG_PATH = Path(__file__).resolve().parents[1] / "logs" / "waf_logs.jsonl"

def write_log(payload: str, result: dict, ip: str = "local"):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "payload": payload,
        "decision": result.get("decision"),
        "threats": result.get("threats", []),
        "ai_confidence": result.get("ai_confidence")
    }

    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")