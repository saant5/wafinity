import re

BOT_PATTERNS = [
    r"curl",
    r"wget",
    r"python-requests",
    r"scrapy",
    r"httpclient",
    r"libwww",
    r"go-http-client"
]

def is_bot(user_agent):
    if not user_agent:
        return True
    ua = user_agent.lower()
    for b in BOT_PATTERNS:
        if re.search(b, ua):
            return True
    return False