import json
from datetime import datetime

def generate_report(findings, url):
    report = {
        "target": url,
        "scan_time": str(datetime.now()),
        "total_findings": len(findings),
        "findings": findings
    }

    with open("reports/report.json", "w") as f:
        json.dump(report, f, indent=4)

    with open("reports/report.txt", "w") as f:
        f.write("=== WAFinity Enterprise Vulnerability Report ===\n")
        f.write(f"Target: {url}\n")
        f.write(f"Scan Time: {report['scan_time']}\n\n")

        for i, finding in enumerate(findings, 1):
            f.write(f"\n--- Finding {i} ---\n")
            f.write(str(finding))
            f.write("\n")

    return "reports/report.json", "reports/report.txt"