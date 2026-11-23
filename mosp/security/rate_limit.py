from __future__ import annotations

import ipaddress
import math
import time
import uuid
from typing import Tuple

from redis import Redis

from mosp import host
from mosp.security.client_ip import request_ip as client_ip
from mosp.security.names import login_key, login_name, printable_name

__all__ = [
    "address_allowance",
    "address_window_allow",
    "client_ip",
    "fixed_window_allow",
    "fixed_window_spend",
    "login_key",
    "login_name",
    "printable_name",
    "sliding_window_allow",
]


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
