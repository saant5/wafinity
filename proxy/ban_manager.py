from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


# ---- Config: escalation ladder ----
# number of BLOCK events -> ban duration
# after last step => permanent ban
ESCALATION_SECONDS = [
    2 * 60,        # 1st ban: 2 minutes
    10 * 60,       # 2nd ban: 10 minutes
    60 * 60,       # 3rd ban: 1 hour
]
PERMANENT_AFTER = 4  # 4th ban => permanent


@dataclass
class BanInfo:
    ban_count: int = 0              # how many times this IP was banned
    blocked_events: int = 0         # how many BLOCK events total (for stats)
    banned_until: float = 0.0       # epoch seconds; 0 means not currently banned
    is_permanent: bool = False


_state: Dict[str, BanInfo] = {}


def _now() -> float:
    return time.time()


def is_banned(ip: str) -> Tuple[bool, Optional[int]]:
    """
    Returns (True, remaining_seconds) if banned.
    remaining_seconds is None when permanent.
    """
    info = _state.get(ip)
    if not info:
        return (False, None)

    if info.is_permanent:
        return (True, None)

    if info.banned_until > _now():
        return (True, int(info.banned_until - _now()))

    return (False, None)


def record_block(ip: str) -> BanInfo:
    """
    Call this when you BLOCK an IP for any reason (attack, rate limit, bot).
    If IP crosses threshold, it escalates ban.
    """
    info = _state.setdefault(ip, BanInfo())
    info.blocked_events += 1
    return info


def escalate_ban(ip: str) -> BanInfo:
    """
    Escalate ban level (2m -> 10m -> 1h -> permanent).
    """
    info = _state.setdefault(ip, BanInfo())

    # If already permanent, keep it
    if info.is_permanent:
        return info

    info.ban_count += 1

    if info.ban_count >= PERMANENT_AFTER:
        info.is_permanent = True
        info.banned_until = 0.0
        return info

    # pick duration from ladder (ban_count=1 => first duration)
    idx = max(0, info.ban_count - 1)
    duration = ESCALATION_SECONDS[min(idx, len(ESCALATION_SECONDS) - 1)]
    info.banned_until = _now() + duration
    return info


def ban_level_text(info: BanInfo) -> str:
    if info.is_permanent:
        return "PERMANENT"
    if info.ban_count <= 0:
        return "NONE"
    if info.ban_count == 1:
        return "2_MIN"
    if info.ban_count == 2:
        return "10_MIN"
    if info.ban_count == 3:
        return "1_HOUR"
    return "UNKNOWN"