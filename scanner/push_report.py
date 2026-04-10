import requests

def push_report(report: dict):
    try:
        r = requests.post(
            "http://127.0.0.1:8000/api/v1/scans",
            json=report,
            timeout=10
        )
        print("📡 Sent report:", r.status_code)
        print("📩 Response:", r.json())
    except Exception as e:
        print("❌ Failed to push report:", e)