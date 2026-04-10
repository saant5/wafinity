import requests
import certifi
from datetime import datetime

DEFAULT_HEADERS = {"User-Agent": "WAFinityEnterpriseScanner/1.0"}

PAYLOADS = [
    ("SQLI", "' OR 1=1 --"),
    ("XSS", "<script>alert(1)</script>"),
    ("TRAVERSAL", "../../etc/passwd"),
    ("CMD", "test; whoami"),
]

SQL_ERROR_SIGNS = [
    "you have an error in your sql syntax",
    "sqlstate",
    "syntax error",
    "unclosed quotation",
    "odbc",
    "sqlite error"
]

def looks_like_sql_error(text: str) -> bool:
    t = (text or "").lower()
    return any(s in t for s in SQL_ERROR_SIGNS)

def looks_reflected(payload: str, text: str) -> bool:
    return payload.lower() in (text or "").lower()

def classify_reflection(kind: str):
    # severity + confidence baseline
    if kind == "XSS":
        return ("REFLECTED_XSS", "HIGH", 90)
    if kind == "SQLI":
        return ("SQLI_REFLECTION", "HIGH", 80)
    if kind == "CMD":
        return ("CMD_REFLECTION", "CRITICAL", 95)
    if kind == "TRAVERSAL":
        return ("TRAVERSAL_REFLECTION", "MEDIUM", 65)
    return ("REFLECTION", "LOW", 40)

def submit_form(action_url: str, method: str, data: dict, timeout: int = 10):
    method = (method or "get").lower()
    if method == "post":
        r = requests.post(action_url, data=data, headers=DEFAULT_HEADERS, timeout=timeout,
                          allow_redirects=True, verify=certifi.where())
    else:
        r = requests.get(action_url, params=data, headers=DEFAULT_HEADERS, timeout=timeout,
                         allow_redirects=True, verify=certifi.where())
    return r.status_code, r.url, r.text

def test_form(form: dict):
    findings = []
    inputs = form.get("inputs", [])
    names = [i["name"] for i in inputs if i.get("name")]

    if not names:
        return findings

    # baseline
    baseline_data = {n: "test" for n in names}
    try:
        base_status, base_url, base_body = submit_form(form["action"], form["method"], baseline_data)
    except Exception as e:
        findings.append({"type": "REQUEST_ERROR", "detail": str(e)})
        return findings

    for kind, payload in PAYLOADS:
        inj_data = {n: payload for n in names}

        try:
            status, final_url, body = submit_form(form["action"], form["method"], inj_data)
        except Exception as e:
            findings.append({"type": "REQUEST_ERROR", "detail": str(e), "payload": payload})
            continue

        # SQL error-based signal
        if kind == "SQLI" and looks_like_sql_error(body) and not looks_like_sql_error(base_body):
            findings.append({
                "type": "POSSIBLE_SQLI_ERROR_BASED",
                "severity": "HIGH",
                "confidence": 85,
                "payload": payload,
                "status": status,
                "url": final_url,
                "time": datetime.now().isoformat(timespec="seconds")
            })

        # Reflection-based signal (classified by payload kind)
        if looks_reflected(payload, body) and not looks_reflected(payload, base_body):
            ftype, sev, conf = classify_reflection(kind)
            findings.append({
                "type": ftype,
                "severity": sev,
                "confidence": conf,
                "payload": payload,
                "status": status,
                "url": final_url,
                "time": datetime.now().isoformat(timespec="seconds")
            })

    return findings