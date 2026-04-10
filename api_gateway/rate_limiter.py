import time
from collections import defaultdict, deque

# In-memory sliding window rate limiter (demo)
# limit requests per IP per window_seconds
class RateLimiter:
    def __init__(self, limit=30, window_seconds=60):
        self.limit = limit
        self.window = window_seconds
        self.hits = defaultdict(deque)

    def allow(self, ip: str) -> bool:
        now = time.time()
        q = self.hits[ip]

        # remove old timestamps
        while q and now - q[0] > self.window:
            q.popleft()

        if len(q) >= self.limit:
            return False

        q.append(now)
        return True