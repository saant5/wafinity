from scanner.fetcher import fetch_url
from scanner.crawler import extract_links, same_origin
from scanner.form_scanner import extract_forms
from scanner.injector import test_form
from scanner.push_report import push_report
from scanner.push_report import push_report

from reports.report_writer import save_report
from datetime import datetime


def crawl_site(seed_url: str, max_pages: int = 10):
    """
    Simple BFS crawl (same-origin only). Returns list of visited URLs.
    """
    visited = []
    queue = [seed_url]

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue

        data = fetch_url(url)
        if not data or not data.get("ok"):
            visited.append(url)  # mark visited even if fetch fails
            continue

        visited.append(data["final_url"])

        # discover more links
        for link in extract_links(data["final_url"], data["body"]):
            if same_origin(seed_url, link) and link not in visited and link not in queue:
                queue.append(link)

    # de-dup while preserving order
    out = []
    for u in visited:
        if u not in out:
            out.append(u)
    return out


def _bump_severity(summary: dict, severity: str):
    """
    Increase severity counters safely.
    """
    sev = (severity or "").strip().lower()
    if sev in ("critical", "high", "medium", "low"):
        summary[sev] += 1


def site_active_scan(seed_url: str, max_pages: int = 10):
    
    report = {
        "type": "SITE_ACTIVE_SCAN",
        "seed_url": seed_url,
        "max_pages": max_pages,
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "pages": [],
        "summary": {
            "pages": 0,
            "forms": 0,
            "findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
    }
    push_report(report)

    print(f"\n🕸️ Site scan starting: {seed_url}")
    pages = crawl_site(seed_url, max_pages=max_pages)
    print(f"📌 Pages discovered: {len(pages)}")

    for p in pages:
        data = fetch_url(p)
        if not data or not data.get("ok"):
            print(f"\n❌ Skip (fetch failed): {p}")
            continue

        report["summary"]["pages"] += 1

        forms = extract_forms(data["final_url"], data["body"])
        page_entry = {"url": data["final_url"], "forms": []}

        if not forms:
            # still record the page (optional). If you don't want empty pages in report, remove next line.
            report["pages"].append(page_entry)
            continue

        print(f"\n📄 Page: {data['final_url']}  | Forms: {len(forms)}")

        for idx, f in enumerate(forms, start=1):
            report["summary"]["forms"] += 1

            print(
                f"  FORM #{idx} -> {f['method'].upper()} {f['action']}  "
                f"inputs={[i['name'] for i in f['inputs']]}"
            )

            findings = test_form(f)

            # store form details in report (even if findings empty)
            form_entry = {
                "action": f["action"],
                "method": f["method"],
                "inputs": [i["name"] for i in f["inputs"]],
                "findings": findings
            }
            page_entry["forms"].append(form_entry)

            if findings:
                print("  🚨 Findings:")
                for x in findings:
                    print("   -", x)

                    report["summary"]["findings"] += 1
                    _bump_severity(report["summary"], x.get("severity"))
            else:
                print("  ✅ No obvious findings")

        # append this page's report data
        report["pages"].append(page_entry)

    report["finished_at"] = datetime.now().isoformat(timespec="seconds")

    print("\n✅ Site scan complete.")
    s = report["summary"]
    print(f"🧾 Pages scanned : {s['pages']}")
    print(f"🧾 Forms scanned : {s['forms']}")
    print(f"🚨 Findings      : {s['findings']}")
    print(f"CRITICAL         : {s['critical']}")
    print(f"HIGH             : {s['high']}")
    print(f"MEDIUM           : {s['medium']}")
    print(f"LOW              : {s['low']}")

    saved_path = save_report(report)
    print("📄 Report saved to:", saved_path)

    return report