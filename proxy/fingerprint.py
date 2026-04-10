import hashlib

def fingerprint(ip, headers, ua):
    raw = f"{ip}|{headers}|{ua}"
    return hashlib.sha256(raw.encode()).hexdigest()