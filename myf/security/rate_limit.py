from __future__ import annotations

import ipaddress
import math
import time
import unicodedata
import uuid
from typing import Tuple

from redis import Redis

from myf import host
from myf.security.client_ip import request_ip as client_ip

__all__ = [
    "address_allowance",
    "address_window_allow",
    "client_ip",
    "fixed_window_allow",
    "fixed_window_spend",
    "login_name",
    "sliding_window_allow",
]

# Unicode Default_Ignorable_Code_Point ranges, plus the object replacement
# character that RFC 4518 also maps to nothing. Directories ignore these when
# they compare names, so they never distinguish one username from another.
_IGNORABLE = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0xFFFC, 0xFFFC),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)


def _ignorable(character: str) -> bool:
    point = ord(character)
    if unicodedata.category(character) == "Cc" and not character.isspace():
        return True
    return any(low <= point <= high for low, high in _IGNORABLE)


# Line breaks and control or format characters (bidirectional overrides among
# them) make one name look like another, so no account name holds them.
_UNPRINTED = frozenset({"Cc", "Cf", "Zl", "Zp"})


def printable_name(username: str) -> bool:
    """Whether a username holds no control, format or line-break character."""
    return not any(unicodedata.category(c) in _UNPRINTED for c in username)


def login_name(username: str) -> str:
    """The form in which sign-in names are compared for rate limiting.

    Directories match names regardless of width, case, invisible characters and
    runs of spaces (Active Directory folds fullwidth forms; RFC 4518 drops
    ignorable characters and collapses spaces), so every such variant of a
    name has one form. An empty form means the username is effectively blank.
    """
    folded = unicodedata.normalize(
        "NFKC", unicodedata.normalize("NFKC", username).casefold()
    )
    visible = "".join(c for c in folded if not _ignorable(c))
    return " ".join(visible.split())


def address_allowance(address: str | None) -> str | None:
    """The part of a client address that a per-address allowance counts.

    One IPv6 subscriber or host normally holds a whole /64 network, so every
    address in it shares one allowance; an IPv4 address has its own.
    """
    if address is None:
        return None
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        return str(ipaddress.IPv6Network((ip, 64), strict=False))
    return str(ip)


def address_window_allow(
    r: Redis,
    scope: str,
    address: str | None,
    limit: int,
    window_seconds: int,
    fail_closed: bool = False,
) -> Tuple[bool, int]:
    """A fixed-window allowance for one client address.

    Every per-address limit goes through here, so each counts an IPv6 /64
    network as one address. Clients whose address is unknown share one
    allowance. The contract tests refuse a client address in any other
    allowance key.
    """
    allowance = address_allowance(address) or "unknown"
    return fixed_window_allow(
        r,
        f"{host.name()}:rl:{scope}:ip:{allowance}",
        limit,
        window_seconds,
        fail_closed,
    )


def fixed_window_allow(
    r: Redis, key: str, limit: int, window_seconds: int, fail_closed: bool = False
) -> Tuple[bool, int]:
    """Fixed-window rate limiting using Redis/Valkey.

    Returns (allowed, retry_after_seconds).

    Implementation:
      - INCR a counter
      - Ensure the key has an expiry
      - Read TTL for Retry-After

    Args:
        r: Redis client
        key: Rate limit key
        limit: Maximum requests allowed
        window_seconds: Time window in seconds
        fail_closed: If True, deny requests when Redis is unavailable.
                    If False, allow requests (fail open) when Redis is unavailable.
    """
    if limit <= 0 or window_seconds <= 0:
        return True, 0

    try:
        # Pipeline for minimal round-trips.
        pipe = r.pipeline()
        pipe.incr(key)
        pipe.ttl(key)
        count, ttl = pipe.execute()

        try:
            count_i = int(count)
        except Exception:
            count_i = limit + 1

        try:
            ttl_i = int(ttl)
        except Exception:
            ttl_i = int(window_seconds)

        # Redis TTL can be -1 (no expiry) or -2 (missing). Ensure the key expires.
        if ttl_i < 0:
            try:
                r.expire(key, int(window_seconds))
            except Exception:
                pass
            ttl_i = int(window_seconds)

        if count_i > int(limit):
            return False, ttl_i
        return True, 0
    except Exception:
        # Redis unavailable
        if fail_closed:
            return False, window_seconds
        return True, 0


def fixed_window_spend(
    r: Redis,
    key: str,
    amount: int,
    limit: int,
    window_seconds: int,
    fail_closed: bool = False,
) -> Tuple[bool, int]:
    """Spend ``amount`` from a fixed-window allowance of ``limit`` units.

    Counts cost (such as bytes) rather than requests. A spend that would pass
    the limit is refused and still counted, so a caller that keeps sending
    over its allowance stays refused until the window ends.
    """
    if limit <= 0 or window_seconds <= 0:
        return True, 0
    try:
        pipe = r.pipeline()
        pipe.incrby(key, max(0, int(amount)))
        pipe.ttl(key)
        spent, ttl = pipe.execute()
        ttl_i = int(ttl)
        if ttl_i < 0:
            r.expire(key, int(window_seconds))
            ttl_i = int(window_seconds)
        if int(spent) > int(limit):
            return False, ttl_i
        return True, 0
    except Exception:
        if fail_closed:
            return False, window_seconds
        return True, 0


def sliding_window_allow(
    r: Redis,
    key: str,
    limit: int,
    window_seconds: int,
    *,
    fail_closed: bool = True,
    now: float | None = None,
) -> Tuple[bool, int]:
    """Admit at most ``limit`` attempts in any ``window_seconds``.

    For costly work, where a fixed window's boundary would let twice the
    limit through in quick succession. Each admitted attempt is kept, as a
    member of a sorted set scored by its time, until it leaves the window. An
    attempt is added and counted in one transaction; one that would pass the
    limit is taken back and refused, with the wait until the oldest counted
    attempt leaves. Attempts made together may each be refused where one
    would have been admitted, never the other way round.
    """
    if limit <= 0 or window_seconds <= 0:
        return True, 0
    moment = time.time() if now is None else float(now)
    member = uuid.uuid4().hex
    try:
        pipe = r.pipeline(transaction=True)
        pipe.zremrangebyscore(key, "-inf", moment - window_seconds)
        pipe.zadd(key, {member: moment})
        pipe.zcard(key)
        pipe.expire(key, int(window_seconds))
        _, _, count, _ = pipe.execute()
        if int(count) <= int(limit):
            return True, 0
        r.zrem(key, member)
        oldest = r.zrange(key, 0, 0, withscores=True)
        first = float(oldest[0][1]) if oldest else moment
        return False, max(1, math.ceil(first + window_seconds - moment))
    except Exception:
        if fail_closed:
            return False, window_seconds
        return True, 0
