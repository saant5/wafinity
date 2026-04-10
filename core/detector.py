import re

SQLI_PATTERNS = [
    r"(?i)union\s+select",
    r"(?i)or\s+1=1",
    r"(?i)drop\s+table",
    r"--"
]

XSS_PATTERNS = [
    r"(?i)<script>",
    r"(?i)onerror=",
    r"(?i)javascript:"
]

CMD_PATTERNS = [
    r";",
    r"\|\|",
    r"&&"
]

def detect_patterns(payload: str):
    threats = []

    for pattern in SQLI_PATTERNS:
        if re.search(pattern, payload):
            threats.append("SQL_INJECTION")

    for pattern in XSS_PATTERNS:
        if re.search(pattern, payload):
            threats.append("XSS")

    for pattern in CMD_PATTERNS:
        if re.search(pattern, payload):
            threats.append("COMMAND_INJECTION")

    return list(set(threats))