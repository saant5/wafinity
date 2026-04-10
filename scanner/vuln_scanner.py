from core.threat_engine import analyze

ATTACK_PAYLOADS = [
    "' OR 1=1 --",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "' UNION SELECT NULL,NULL --",
    "admin' --"
]

def attack_endpoint(target):
    results = []

    for payload in ATTACK_PAYLOADS:
        res = analyze(payload)

        results.append({
            "target": target,
            "payload": payload,
            "analysis": res
        })

    return results