import json
import os

BASE_DIR = os.path.dirname(__file__)
FEED_FILE = os.path.join(BASE_DIR, "feeds.json")

with open(FEED_FILE, "r") as f:
    FEEDS = json.load(f)

BLACKLIST = FEEDS.get("blacklist", [])
SUSPICIOUS_RANGES = FEEDS.get("suspicious_ranges", [])

def check_ip(ip: str):
    score = 0
    flags = []

    # Exact blacklist
    if ip in BLACKLIST:
        score += 50
        flags.append("BLACKLISTED_IP")

    # Range check
    for prefix in SUSPICIOUS_RANGES:
        if ip.startswith(prefix):
            score += 20
            flags.append("SUSPICIOUS_RANGE")
            break

    return score, flags