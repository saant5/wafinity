from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque, Dict

# ---- Config ----
WINDOW_SECONDS = 60          # 1 minute window
MAX_REQUESTS = 30            # max requests per window per IP
BLOCK_SECONDS = 120          # block IP for 2 minutes after limit exceeded


# Per-IP request timestamps
_requests: Dict[str, Deque[float]] = defaultdict(deque)

# Per-IP block-until timestamp
_blocked_until: Dict[str, float] = {}


def rate_limit(ip: str) -> bool:
    """
    Returns True if allowed, False if blocked by rate limiting.
    """
    now = time.time()

    # If already blocked
    until = _blocked_until.get(ip)
    if until and now < until:
        return False

    q = _requests[ip]
    q.append(now)

    # Remove old timestamps
    cutoff = now - WINDOW_SECONDS
    while q and q[0] < cutoff:
        q.popleft()

    # Check limit
    if len(q) > MAX_REQUESTS:
        _blocked_until[ip] = now + BLOCK_SECONDS
        return False

    return True


def status(ip: str):
    """
    Optional: useful for debug/monitoring
    """
    now = time.time()
    q = _requests.get(ip, deque())
    cutoff = now - WINDOW_SECONDS
    recent = [t for t in q if t >= cutoff]
    blocked = _blocked_until.get(ip, 0) > now
    return {
        "recent_requests": len(recent),
        "blocked": blocked,
        "blocked_for_seconds": max(0, int(_blocked_until.get(ip, 0) - now)),
        "max_requests": MAX_REQUESTS,
        "window_seconds": WINDOW_SECONDS,
    }