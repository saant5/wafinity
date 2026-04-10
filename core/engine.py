import re
import urllib.parse
import base64

SQLI = [
    r"(?i)union\s+select",
    r"(?i)or\s+1=1",
    r"(?i)drop\s+table",
    r"--",
]

XSS = [
    r"(?i)<script>",
    r"(?i)onerror=",
    r"(?i)onload=",
    r"(?i)javascript:",
]

CMD = [
    r";",
    r"\|\|",
    r"&&",
]

TRAVERSAL = [
    r"\.\./",
    r"\.\.\\",
]


def decode_payload(payload: str):
    variants = [payload]

    # URL decode
    try:
        variants.append(urllib.parse.unquote(payload))
    except:
        pass

    # Base64 decode (best-effort)
    try:
        decoded = base64.b64decode(payload).decode("utf-8", errors="ignore")
        if decoded.strip():
            variants.append(decoded)
    except:
        pass

    # normalize
    out = []
    for v in variants:
        out.append(v.lower())
    return list(set(out))


def detect(payload: str):
    decoded_versions = decode_payload(payload)
    threats = []

    for version in decoded_versions:
        for pattern in SQLI:
            if re.search(pattern, version):
                threats.append("SQL_INJECTION")

        for pattern in XSS:
            if re.search(pattern, version):
                threats.append("XSS")

        for pattern in CMD:
            if re.search(pattern, version):
                threats.append("COMMAND_INJECTION")

        for pattern in TRAVERSAL:
            if re.search(pattern, version):
                threats.append("PATH_TRAVERSAL")

    threats = list(set(threats))
    risk_score = min(len(threats) * 30, 100)

    return {
        "threats": threats,
        "risk_score": risk_score,
        "malicious": len(threats) > 0
    }