from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
from datetime import datetime

app = FastAPI(title="WAFinity API")

# Temporary in-memory store (later: MongoDB)
SCAN_STORE: List[Dict[str, Any]] = []

class ScanReport(BaseModel):
    type: str
    seed_url: str
    max_pages: int
    started_at: str
    finished_at: Optional[str] = None
    pages: list
    summary: Dict[str, Any]

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/api/v1/scans")
def save_scan(report: ScanReport):
    item = report.model_dump()  # pydantic v2
    item["received_at"] = datetime.now().isoformat(timespec="seconds")
    SCAN_STORE.append(item)
    return {"status": "ok", "stored": len(SCAN_STORE)}

@app.get("/api/v1/scans")
def list_scans():
    return SCAN_STORE