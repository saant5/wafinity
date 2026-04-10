from core.threat_engine import analyze
from scanner.fetcher import fetch_url
from scanner.scanner import scan_page
from scanner.crawler import crawl
from scanner.vuln_scanner import attack_endpoint
from reports.report_generator import generate_report
from core.threat_engine import analyze
from core.threat_engine import analyze
from core.logger import write_log

while True:
    payload = input("Enter payload: ")
    result = analyze(payload)
    write_log(payload, result)
    print(result)
    print("-" * 50)
while True:
    payload = input("Enter payload: ")
    result = analyze(payload)
    print(result)
    print("-" * 50)
print("=== WAFinity Enterprise XDR ===")

print("\nModes:")
print("1 - Payload Scan")
print("2 - URL Scan")
print("3 - Full Vulnerability Scan + Report")

mode = input("\nSelect mode: ")

if mode == "1":
    while True:
        payload = input("\nEnter payload (or 'exit'): ")
        if payload.lower() == "exit":
            break
        print(analyze(payload))

elif mode == "2":
    url = input("\nEnter website URL: ")
    html = fetch_url(url)
    if not html:
        print("Failed to fetch website")
    else:
        findings = scan_page(html)
        for f in findings:
            print(f)

elif mode == "3":
    url = input("\nEnter target URL: ")

    print("\n[+] Crawling website...")
    endpoints = crawl(url, depth=1)

    all_findings = []

    print("[+] Attacking endpoints...")
    for ep in endpoints:
        results = attack_endpoint(ep)
        all_findings.extend(results)

    print("\n[+] Generating report...")
    json_report, txt_report = generate_report(all_findings, url)

    print("\n=== SCAN COMPLETE ===")
    print("JSON Report:", json_report)
    print("Text Report:", txt_report)