import json
import re
from api_security.api_firewall import api_firewall

# Allowed endpoints + methods
API_RULES = {
    "/get": ["GET"],
    "/post": ["POST"],
    "/login": ["POST"],
    "/users": ["GET", "POST"],
}

# Sensitive keywords
SENSITIVE_PATTERNS = [
    r"password",
    r"creditcard",
    r"ssn",
    r"api_key",
    r"secret",
    r"token"
]

def validate_endpoint(path, method):
    if path not in API_RULES:
        return False, "UNKNOWN_ENDPOINT"
    if method not in API_RULES[path]:
        return False, "INVALID_METHOD"
    return True, None

def inspect_json_body(body):
    try:
        data = json.loads(body)
    except:
        return []

    findings = []

    body_str = json.dumps(data).lower()

    for pattern in SENSITIVE_PATTERNS:
        if re.search(pattern, body_str):
            findings.append("SENSITIVE_DATA_EXPOSURE")

    return findings

def api_firewall(path, method, body):
    detected = []

    # Endpoint validation
    valid, error = validate_endpoint(path, method)
    if not valid:
        detected.append(error)

    # JSON inspection
    if body:
        findings = inspect_json_body(body)
        detected.extend(findings)

    return detected