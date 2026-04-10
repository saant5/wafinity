from scanner.fetcher import fetch_url
from scanner.form_scanner import extract_forms
from scanner.injector import test_form
from reports.report_writer import save_report

def active_scan(url: str):
    data = fetch_url(url)
    report = {"target": url, "forms": [], "summary": {"findings": 0}}

    if data is None or not data.get("ok"):
        print("❌ Fetch failed:", (data or {}).get("error_type"))
        print((data or {}).get("error"))
        return

    print(f"\n✅ Loaded: {data['final_url']}  (status={data['status_code']})")
    forms = extract_forms(data["final_url"], data["body"])

    print(f"🧾 Forms found: {len(forms)}")
    if not forms:
        print("ℹ️ No forms found. Pick a page that has a login/search form.")
        return

    for idx, f in enumerate(forms, start=1):
        print("\n" + "=" * 60)
        print(f"FORM #{idx}")
        print("Action:", f["action"])
        print("Method:", f["method"])
        print("Inputs:", [i["name"] for i in f["inputs"]])

        findings = test_form(f)
        if findings:
            print("🚨 Findings:")
            for x in findings:
                print(" -", x)
        else:
            print("✅ No obvious findings (demo heuristics).")
            report["forms"].append({
    "action": f["action"],
    "method": f["method"],
    "inputs": [i["name"] for i in f["inputs"]],
    "findings": findings
})
        report["summary"]["findings"] += len(findings)

    print("\n✅ Active scan complete.")