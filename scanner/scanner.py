from bs4 import BeautifulSoup
from core.threat_engine import analyze

def scan_page(html):
    soup = BeautifulSoup(html, "html.parser")
    findings = []

    # Scan forms
    for form in soup.find_all("form"):
        action = form.get("action")
        inputs = form.find_all("input")

        for inp in inputs:
            name = inp.get("name", "unknown")
            test_payload = "' OR 1=1 --"

            result = analyze(test_payload)

            findings.append({
                "type": "FORM_INPUT",
                "field": name,
                "action": action,
                "result": result
            })

    # Scan URL parameters
    for link in soup.find_all("a", href=True):
        if "?" in link["href"]:
            test_payload = link["href"] + "' OR 1=1 --"
            result = analyze(test_payload)

            findings.append({
                "type": "URL_PARAM",
                "url": link["href"],
                "result": result
            })

    return findings