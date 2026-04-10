from scanner.url_scanner import scan_url
from scanner.active_scan import active_scan
from scanner.site_scan import site_active_scan
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any, Dict
from datetime import datetime

app = FastAPI()

# Temporary storage (later we move to MongoDBpppp)
SCAN_STORE = []

class ScanReport(BaseModel):
    type: str
    seed_url: str
    max_pages: int
    started_at: str
    finished_at: str | None = None
    pages: list
    summary: Dict[str, Any]

@app.post("/api/v1/scans")
def save_scan(report: ScanReport):
    item = report.dict()
    item["received_at"] = datetime.now().isoformat(timespec="seconds")
    SCAN_STORE.append(item)
    return {"status": "ok", "stored": len(SCAN_STORE)}

if __name__ == "__main__":
    print("\nWAFinity Scanner Modes")
    print("1) Passive URL Scan (query params + light HTML)")
    print("2) Active Form Scan (one page)")
    print("3) Site Active Scan (crawl + scan all forms)\n")

    choice = input("Choose mode (1/2/3): ").strip()

    if choice == "1":
        target = input("Enter URL to scan: ").strip()
        scan_url(target, crawl_limit=5)

    elif choice == "2":
        target = input("Enter URL to active-scan (authorized only): ").strip()
        active_scan(target)

    elif choice == "3":
        target = input("Enter site URL to crawl+scan (authorized only): ").strip()
        max_pages = input("Max pages (default 10): ").strip()
        max_pages = int(max_pages) if max_pages.isdigit() else 10
        site_active_scan(target, max_pages=max_pages)

    else:
        print("❌ Invalid choice")