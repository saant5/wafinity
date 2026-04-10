from __future__ import annotations
import time
from collections import defaultdict, deque
from typing import Deque, Dict

WINDOW_SECONDS = 60
MAX_REQUESTS_PER_USER = 20

_user_hits: Dict[str, Deque[float]] = defaultdict(deque)

def allow_user(user_id: str) -> bool:
    now = time.time()
    q = _user_hits[user_id]
    q.append(now)
    cutoff = now - WINDOW_SECONDS
    while q and q[0] < cutoff:
        q.popleft()
    return len(q) <= MAX_REQUESTS_PER_USER