import json
from datetime import datetime
from pathlib import Path

def save_report(report: dict, folder: str = "reports"):
    Path(folder).mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = Path(folder) / f"scan_{ts}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return str(path)