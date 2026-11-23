"""A browser's notification socket: its origin, handshake allowance, account
checks on a schedule, connection cap and frame bound."""

import asyncio
from contextlib import ExitStack, contextmanager
from unittest.mock import Mock

import pytest
from starlette.routing import WebSocketRoute
from starlette.websockets import WebSocketDisconnect

from mosp.realtime import notifications, sockets
from tests.assembled import BASE
from tests.testapp import main

ORIGIN = {"Origin": BASE}


def _signed_in(client):
    """The handshake headers of a browser holding ``client``'s cookies.

    The test client opens sockets on its own host, where the session's
    __Host- cookie would not be sent, so the cookies travel as a header.
    """
    jar = "; ".join(f"{name}={value}" for name, value in client.cookies.items())
    return {**ORIGIN, "Cookie": jar}


@contextmanager
def _mounted(path, endpoint):
    """``endpoint`` served at ``path`` on the test application for a while."""
    main.app.router.routes.insert(0, WebSocketRoute(path, endpoint))
    try:
        yield
    finally:
        main.app.router.routes.pop(0)


@pytest.fixture
def signed_in(site, monkeypatch):
    monkeypatch.setattr(sockets, "RECHECK_SECONDS", 0.01)
    user = site.user()
    return site, site.client(user), user


def test_a_socket_from_another_origin_is_refused_before_any_lookup(site, monkeypatch):
    snapshot = Mock()
    monkeypatch.setattr(sockets, "signed_in_snapshot", snapshot)
    with pytest.raises(WebSocketDisconnect) as closed:
        with site.client().websocket_connect(
            "/ws/notifications", headers={"Origin": "https://evil.example"}
        ):
            pass
    assert (closed.value.code, closed.value.reason) == (1008, "Origin not allowed")
    snapshot.assert_not_called()


def test_a_socket_without_a_session_is_refused(site):
    with pytest.raises(WebSocketDisconnect) as closed:
        with site.client().websocket_connect("/ws/notifications", headers=ORIGIN):
            pass
    assert (closed.value.code, closed.value.reason) == (1008, "")


def test_a_socket_is_pinged_until_its_account_changes(signed_in):
    site, client, user = signed_in
    with client.websocket_connect(
        "/ws/notifications", headers=_signed_in(client)
    ) as socket:
        assert socket.receive_json() == {"type": "ping"}
        user.authz_version = (user.authz_version or 0) + 1
        site.db.commit()
        with pytest.raises(WebSocketDisconnect) as closed:
            for _ in range(50):
                assert socket.receive_json() == {"type": "ping"}
    assert (closed.value.code, closed.value.reason) == (1008, "")
    assert notifications.notification_hub._user_sockets == {}


def test_a_socket_closes_after_sign_out(signed_in):
    site, client, user = signed_in
    with client.websocket_connect(
        "/ws/notifications", headers=_signed_in(client)
    ) as socket:
        assert socket.receive_json() == {"type": "ping"}
        for key in site.store.keys("testapp:session:*"):
            site.store.delete(key)
        with pytest.raises(WebSocketDisconnect):
            for _ in range(50):
                socket.receive_json()


def test_each_account_has_a_bounded_number_of_sockets(signed_in, monkeypatch):
    site, client, user = signed_in
    monkeypatch.setattr(sockets, "RECHECK_SECONDS", 60)
    with ExitStack() as stack:
        for _ in range(5):
            stack.enter_context(
                client.websocket_connect(
                    "/ws/notifications", headers=_signed_in(client)
                )
            )
        with pytest.raises(WebSocketDisconnect) as refused:
            with client.websocket_connect(
                "/ws/notifications", headers=_signed_in(client)
            ):
                pass
        assert (refused.value.code, refused.value.reason) == (
            1008,
            "Too many notification connections",
        )
    assert notifications.notification_hub._user_sockets == {}


def test_an_oversized_client_frame_closes_the_socket(signed_in, monkeypatch):
    site, client, user = signed_in
    monkeypatch.setattr(sockets, "RECHECK_SECONDS", 60)
    with client.websocket_connect(
        "/ws/notifications", headers=_signed_in(client)
    ) as socket:
        socket.send_text("x" * 1024)
        socket.send_text("x" * 1025)
        with pytest.raises(WebSocketDisconnect) as closed:
            socket.receive_json()
    assert (closed.value.code, closed.value.reason) == (1008, "")


def test_handshakes_are_bounded_for_each_address(site, monkeypatch):
    snapshot = Mock(return_value=None)
    monkeypatch.setattr(sockets, "HANDSHAKES_PER_MINUTE", 2)

    async def served(websocket):
        await sockets.serve(websocket, snapshot)

    reasons = []
    with _mounted("/ws/counted", served):
        for _ in range(3):
            with pytest.raises(WebSocketDisconnect) as closed:
                with site.client().websocket_connect("/ws/counted", headers=ORIGIN):
                    pass
            reasons.append((closed.value.code, closed.value.reason))
    # The third attempt is refused before any session or database work.
    assert reasons == [(1008, ""), (1008, ""), (1008, "Too many connection attempts")]
    assert snapshot.call_count == 2


def test_an_application_snapshot_sends_its_payloads_on_connecting(signed_in):
    site, client, user = signed_in
    hub = notifications.NotificationHub()

    def snapshot(headers, cookies, *, counts=False, peer=None):
        identity = sockets.signed_in_snapshot(headers, cookies, peer=peer)
        if identity is None:
            return None
        return identity[0], [{"type": "counts", "initial": counts}]

    async def served(websocket):
        await sockets.serve(websocket, snapshot, hub=hub)

    with _mounted("/ws/own", served):
        with client.websocket_connect("/ws/own", headers=_signed_in(client)) as socket:
            assert socket.receive_json() == {"type": "counts", "initial": True}
            assert socket.receive_json() == {"type": "ping"}


def test_a_socket_that_already_closed_ends_quietly(monkeypatch):
    # The client went away while a check was due: neither the failed send nor
    # the failed close reaches the server's log.
    class Gone:
        client = None
        headers = {"origin": BASE}
        cookies = {}

        def __init__(self):
            self.accepted = False

        async def accept(self):
            self.accepted = True

        async def receive_text(self):
            raise RuntimeError("disconnected")

        async def close(self, code=1000, reason=None):
            raise RuntimeError("already closed")

    monkeypatch.setattr(sockets, "request_origin_allowed", lambda ws, **kw: True)
    monkeypatch.setattr(sockets, "handshake_allowed", lambda ws: True)
    hub = notifications.NotificationHub()
    socket = Gone()

    def snapshot(headers, cookies, **kw):
        return ("u", False), []

    asyncio.run(sockets.serve(socket, snapshot, hub=hub))
    assert socket.accepted and hub._user_sockets == {}
