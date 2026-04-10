from urllib.parse import urlparse, parse_qs, unquote

from scanner.fetcher import fetch_url
from scanner.crawler import crawl
from core.threat_engine import analyze

def extract_query_payloads(url: str):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    payloads = []
    for k, vals in qs.items():
        for v in vals:
            payloads.append(f"{k}={unquote(v)}")
    return payloads

def scan_url(url: str, crawl_limit: int = 5):
    print("\n🌐 Fetching:", url)

    data = fetch_url(url)

    # ✅ Handle None (if old code accidentally returns None)
    if data is None:
        print("❌ fetch_url() returned None. Please re-check scanner/fetcher.py was saved correctly.")
        return

    # ✅ Handle failed fetch
    if not data.get("ok"):
        print("❌ Fetch failed:", data.get("error_type"))
        print("   ", data.get("error"))
        return

    print(f"✅ Status: {data['status_code']}")
    print(f"🔁 Final URL: {data['final_url']}")
    print(f"📄 Content-Type: {data['content_type']}")

    print("\n🔍 Checking query parameters...")
    qps = extract_query_payloads(url) + extract_query_payloads(data["final_url"])
    qps = list(dict.fromkeys(qps))  # remove duplicates
    if not qps:
        print("ℹ️ No query params found.")
    else:
        for qp in qps:
            res = analyze(qp)
            threats = res.get("threats", [])
            risk = res.get("risk_score", res.get("risk", res.get("score", 0)))
            if threats:
                print("🚨 Threat:", qp, "=>", threats, "Risk:", risk)
            else:
                print("✅ Safe:", qp)

    print(f"\n🕷️ Crawling same-origin pages (limit={crawl_limit})...")
    pages = crawl(data["final_url"], data["body"], limit=crawl_limit)
    for p in pages:
        print(" -", p)

    print("\n✅ Scan complete.")