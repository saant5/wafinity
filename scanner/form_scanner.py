from bs4 import BeautifulSoup
from urllib.parse import urljoin

def extract_forms(page_url: str, html: str):
    soup = BeautifulSoup(html, "html.parser")
    forms_out = []

    for form in soup.find_all("form"):
        action = form.get("action") or page_url
        method = (form.get("method") or "get").lower()
        target = urljoin(page_url, action)

        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or "text").lower()
            inputs.append({"name": name, "type": itype})

        forms_out.append({
            "action": target,
            "method": method,
            "inputs": inputs
        })

    return forms_out