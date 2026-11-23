"""A signed-in browser's notification socket.

``serve(websocket, snapshot)`` runs one connection: its Origin must name the
application, each client address (an IPv6 /64 counts as one) gets a small
allowance of handshakes, and the account is read at the handshake and again
on a schedule. A sign-out, password change, expiry, deactivation or change of
role or permissions since the handshake ends the socket, as it ends the
session's requests; the check follows the clock, not the client's silence.
The connection holds no database session while it is idle.

``snapshot(headers, cookies, counts=..., peer=...)`` returns the account's
identity (its id, whether it is an administrator, and whatever else must not
change while the socket stays open) and the payloads to send on connecting,
or None to refuse. ``signed_in_snapshot`` is the default: the account's
standing and no payloads.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from fastapi import WebSocket
from starlette.concurrency import run_in_threadpool

from myf.realtime.notifications import NotificationHub, notification_hub
from myf.security import auth
from myf.security.auth import get_current_user_from_headers_cookies
from myf.security.client_ip import request_ip
from myf.security.csrf import request_origin_allowed
from myf.security.permissions import ensure_session_authorization_current
from myf.security.rate_limit import address_window_allow
from myf.security.roles import is_effective_admin

# WebSocket handshakes each client address may start a minute.
HANDSHAKES_PER_MINUTE = 30
# Seconds between checks that the socket's account still stands as it did.
RECHECK_SECONDS = 30
# The longest text frame a client may send; the socket carries none it reads.
MAX_CLIENT_FRAME = 1024

Snapshot = Callable[..., "tuple[tuple, list[dict[str, Any]]] | None"]


def signed_in_snapshot(headers, cookies, *, counts=False, peer=None):
    """The signed-in account's standing, and nothing to send on connecting."""
    # Never hold a dependency-scoped transaction for a socket's lifetime.
    from myf.host.db import SessionLocal

    with SessionLocal() as db:
        user = get_current_user_from_headers_cookies(
            headers, cookies, db, refresh_session=False, peer=peer
        )
        if not user:
            return None
        ensure_session_authorization_current(db, user)
        admin = is_effective_admin(db, user)
        return (str(user.id), admin, user.authz_version, user.mfa_version), []


def handshake_allowed(websocket: WebSocket) -> bool:
    # The allowance lives in the store that holds the sessions (auth's
    # connection), and fails closed: without it no session could be checked
    # either.
    allowed, _ = address_window_allow(
        auth.get_valkey(),
        "ws-handshake",
        request_ip(websocket),
        HANDSHAKES_PER_MINUTE,
        60,
        fail_closed=True,
    )
    return allowed


async def serve(
    websocket: WebSocket,
    snapshot: Snapshot = signed_in_snapshot,
    *,
    hub: NotificationHub = notification_hub,
) -> None:
    """Run one notification socket until it closes or its account changes."""
    if not request_origin_allowed(websocket, require_origin=True):
        await websocket.close(code=1008, reason="Origin not allowed")
        return
    # Each handshake costs a session lookup and a database read.
    if not await run_in_threadpool(handshake_allowed, websocket):
        await websocket.close(code=1008, reason="Too many connection attempts")
        return
    peer = getattr(websocket.client, "host", None)
    initial = await run_in_threadpool(
        snapshot, websocket.headers, websocket.cookies, counts=True, peer=peer
    )
    if initial is None:
        await websocket.close(code=1008)
        return
    identity, payloads = initial
    if not await hub.connect(websocket, user_id=identity[0], is_admin=identity[1]):
        await websocket.close(code=1008, reason="Too many notification connections")
        return
    try:
        await websocket.accept()
        for payload in payloads:
            await asyncio.wait_for(websocket.send_json(payload), timeout=5)
        loop = asyncio.get_running_loop()
        next_check = loop.time() + RECHECK_SECONDS
        while True:
            try:
                message = await asyncio.wait_for(
                    websocket.receive_text(), timeout=max(0, next_check - loop.time())
                )
                if len(message) > MAX_CLIENT_FRAME:
                    break
            except asyncio.TimeoutError:
                current = await run_in_threadpool(
                    snapshot, websocket.headers, websocket.cookies, peer=peer
                )
                if current is None or current[0] != identity:
                    break
                await asyncio.wait_for(websocket.send_json({"type": "ping"}), timeout=5)
                next_check = loop.time() + RECHECK_SECONDS
    except Exception:
        pass
    finally:
        await hub.disconnect(websocket)
        try:
            await websocket.close(code=1008)
        except Exception:
            pass
