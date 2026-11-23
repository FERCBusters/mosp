"""Edges of the shared contracts: redaction of odd shapes, rich text, session
storage, cookies, response and body policy, allowances, mailboxes, the host
binding, settings, and the identity provider transport."""

import asyncio
import json
from datetime import datetime, timedelta, timezone

import fakeredis
import httpx2 as httpx
import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from starlette.requests import Request

import myf.host
from myf.core import email_address
from myf.host import hooks
from myf.security import auth, mfa, sessions, sso_http
from myf.security import redaction as r
from myf.security.headers import SecurityHeadersMiddleware
from myf.security.json_shape import MAX_DEPTH, NESTED_TOO_DEEPLY
from myf.security.rate_limit import fixed_window_spend
from myf.security.request_limits import RequestBodyLimitMiddleware
from myf.security.rich_text import rich_text_has_text
from tests.testapp.config import Settings, settings
from tests.testapp.models import User


def _deep(levels):
    value = "leaf"
    for _ in range(levels):
        value = [value]
    return value


# -- redaction ----------------------------------------------------------------


def test_a_json_text_naming_a_member_twice_is_redacted_as_text():
    text = '{"password": "one", "password": "two"}'
    assert "one" not in r.redact_str(text) and "two" not in r.redact_str(text)


def test_urls_lose_their_credentials_and_secret_parameters():
    assert r.redact_url(
        "https://user:pw@host.example/p?token=t&a=1#access_token=x"
    ) == ("https://REDACTED@host.example/p?token=REDACTED&a=1#access_token=REDACTED")
    assert r.redact_url("https://host.example/p#section") == (
        "https://host.example/p#section"
    )
    assert r.redact_url("https://[::1") == r.REDACTED
    assert r.redact_str(None) is None


def test_redaction_and_masking_walk_every_container_to_a_bound():
    for walk in (r.redact_obj, r.mask_event_data_obj):
        assert walk(None) is None
        assert walk({"a": None, "b": (1, "x")}) == {"a": None, "b": (1, "x")}
        deep = walk(_deep(MAX_DEPTH + 5))
        for _ in range(MAX_DEPTH):
            (deep,) = deep
        assert deep == NESTED_TOO_DEEPLY
    assert r.mask_event_data_str(None) is None
    assert r.mask_event_data_obj({"ip": "203.0.113.5"}) == {"ip": "[MASKED_IP]"}


def test_text_content_types_are_named():
    assert r.is_textual_content_type("application/json; charset=utf-8")
    assert not r.is_textual_content_type("image/png")


@pytest.mark.parametrize(
    "document",
    [
        "[" + ",".join(["1"] * 100_001) + "]",
        json.dumps(_deep(MAX_DEPTH + 5)),
    ],
    ids=["too-many-values", "too-deep"],
)
def test_json_artifacts_too_large_to_decode_are_handled_as_text(document):
    secret = ' "password=hunter2 from 203.0.113.5"'
    data = (document[:-1] + "," + secret + "]").encode()

    masked, status = r.mask_event_data_bytes(data, "application/json")
    assert status == "redacted" and b"203.0.113.5" not in masked
    redacted, status = r.redact_bytes(data, "application/json")
    assert status == "redacted" and b"hunter2" not in redacted


def test_a_clean_text_artifact_is_kept_byte_for_byte():
    data = b"nothing secret here"
    assert r.redact_bytes(data, "text/plain") == (data, "clean")


def test_storable_values_are_bounded_in_depth():
    stored = r.storable({"x": _deep(MAX_DEPTH + 5), "n": float("nan")})
    assert stored["n"] == "nan"
    deep = stored["x"]
    for _ in range(MAX_DEPTH - 1):
        (deep,) = deep
    assert deep == NESTED_TOO_DEEPLY


# -- rich text ----------------------------------------------------------------


@pytest.mark.parametrize(
    "value,has_text",
    [
        ("<p>Words</p>", True),
        ("<p> </p><br>", False),
        ("", False),
        (None, False),
    ],
)
def test_rich_text_shows_words_or_nothing(value, has_text):
    assert rich_text_has_text(value) is has_text


# -- sessions -----------------------------------------------------------------


@pytest.fixture
def store():
    return fakeredis.FakeRedis(decode_responses=True)


def test_a_session_without_a_readable_creation_time_has_no_lifetime_left():
    assert sessions.remaining_lifetime({}, 100) == 0
    assert sessions.remaining_lifetime({"created_at": "soon"}, 100) == 0
    assert sessions.remaining_lifetime({"created_at": 5}, 100) == 0


def test_a_stored_session_that_is_not_an_object_is_no_session(store):
    store.set(sessions.session_key("listed"), "[1]")
    store.set(sessions.session_key("broken"), "{")
    assert sessions.get_session(store, "listed") is None
    assert sessions.get_session(store, "broken") is None


def test_an_expired_session_is_ended_and_a_refresh_never_outlives_it(store):
    sid = sessions.create_session(store, user_id="u", ttl_seconds=600)
    key = sessions.session_key(sid)
    payload = json.loads(store.get(key))
    payload["created_at"] = (
        datetime.now(timezone.utc) - timedelta(seconds=90)
    ).isoformat()
    store.set(key, json.dumps(payload), ex=600)

    assert sessions.get_session(
        store, sid, refresh_ttl_seconds=600, max_age_seconds=100
    )
    assert store.ttl(key) <= 10
    assert sessions.get_session(store, sid, max_age_seconds=60) is None
    assert store.get(key) is None


def test_a_permission_refresh_leaves_an_ended_or_expired_session_alone(store):
    refresh = dict(
        effective_role="admin",
        permission_codes=["b", "a", ""],
        authz_version=3,
        ttl_seconds=600,
    )
    sessions.update_session_authz(store, "", **refresh)
    sessions.update_session_authz(store, "gone", **refresh)
    assert store.keys() == []

    store.set(sessions.session_key("listed"), "[1]")
    sessions.update_session_authz(store, "listed", **refresh)
    assert store.get(sessions.session_key("listed")) == "[1]"

    sid = sessions.create_session(store, user_id="u", ttl_seconds=600)
    key = sessions.session_key(sid)
    payload = json.loads(store.get(key))
    payload["created_at"] = "2000-01-01T00:00:00+00:00"
    store.set(key, json.dumps(payload))
    sessions.update_session_authz(store, sid, max_age_seconds=60, **refresh)
    assert "permission_codes" not in json.loads(store.get(key))

    fresh = sessions.create_session(store, user_id="u", ttl_seconds=600)
    sessions.update_session_authz(store, fresh, max_age_seconds=6000, **refresh)
    stored = json.loads(store.get(sessions.session_key(fresh)))
    assert (stored["permission_codes"], stored["authz_version"]) == (["a", "b"], 3)


def test_a_permission_refresh_racing_a_sign_out_writes_nothing(store, monkeypatch):
    from redis.exceptions import WatchError

    sid = sessions.create_session(store, user_id="u", ttl_seconds=600)
    before = store.get(sessions.session_key(sid))
    real = store.pipeline

    def racing(*args, **kwargs):
        pipe = real(*args, **kwargs)

        def execute():
            raise WatchError()

        pipe.execute = execute
        return pipe

    monkeypatch.setattr(store, "pipeline", racing)
    sessions.update_session_authz(
        store,
        sid,
        effective_role="admin",
        permission_codes=[],
        authz_version=1,
        ttl_seconds=600,
    )
    assert store.get(sessions.session_key(sid)) == before


# -- cookies and request identity ---------------------------------------------


def test_cookies_take_the_host_prefix_only_where_the_browser_enforces_it(
    monkeypatch,
):
    monkeypatch.setattr(settings, "cookie_secure", True)
    monkeypatch.setattr(settings, "cookie_domain", "")
    assert auth.cookie_name() == "__Host-testapp_session"
    monkeypatch.setattr(settings, "session_cookie_name", "__Secure-own")
    assert auth.cookie_name() == "__Secure-own"
    monkeypatch.setattr(settings, "cookie_domain", "example.org")
    monkeypatch.setattr(settings, "session_cookie_name", "plain")
    assert auth.cookie_name() == "plain"
    monkeypatch.setattr(settings, "public_base_url", "http://app.example")
    assert mfa.cookie_name() == mfa.COOKIE
    monkeypatch.setattr(settings, "public_base_url", "https://app.example")
    assert mfa.cookie_name() == "__Host-" + mfa.COOKIE


def _request(user=None):
    request = Request({"type": "http", "headers": [], "state": {}})
    request.state.user = user
    return request


def test_routes_name_who_may_use_them():
    with pytest.raises(HTTPException) as anonymous:
        auth.require_authenticated(_request())
    assert (anonymous.value.status_code, anonymous.value.detail) == (
        401,
        "Not authenticated",
    )
    reader = User(username="r", role="normal")
    assert auth.require_authenticated(_request(reader)) is reader
    with pytest.raises(HTTPException) as refused:
        auth.require_admin(_request(reader))
    assert (refused.value.status_code, refused.value.detail) == (
        403,
        "Admin role required",
    )
    reader.effective_role = "admin"
    assert auth.require_admin(_request(reader)) is reader


# -- response and body policy -------------------------------------------------


def test_other_connections_pass_the_response_policy_unchanged():
    seen = []

    async def app(scope, receive, send):
        seen.append(scope["type"])

    asyncio.run(SecurityHeadersMiddleware(app)({"type": "websocket"}, None, None))
    assert seen == ["websocket"]


def _send_through_limit(headers, messages, hook, limit=10):
    hook(body_limit=lambda path: limit)
    received, sent = [], []
    queue = list(messages)

    async def receive():
        return queue.pop(0) if queue else {"type": "http.disconnect"}

    async def app(scope, receive, send):
        while True:
            message = await receive()
            received.append(message)
            if message["type"] != "http.request" or not message.get("more_body"):
                break
        received.append(await receive())

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/things",
        "raw_path": b"/v1/things",
        "query_string": b"",
        "headers": headers,
    }
    asyncio.run(RequestBodyLimitMiddleware(app)(scope, receive, send))
    status = next(
        (m["status"] for m in sent if m["type"] == "http.response.start"), None
    )
    return status, received


@pytest.mark.parametrize(
    "length,status",
    [(b"ten", 400), (b"11", 413), (b"12345678901", 413)],
)
def test_a_declared_length_is_checked_before_the_body_is_read(hook, length, status):
    assert _send_through_limit([(b"content-length", length)], [], hook)[0] == status


def test_a_body_that_outgrows_its_limit_is_refused_before_dispatch(hook):
    status, received = _send_through_limit(
        [],
        [
            {"type": "http.request", "body": b"123456", "more_body": True},
            {"type": "http.request", "body": b"123456", "more_body": False},
        ],
        hook,
    )
    assert (status, received) == (413, [])


def test_a_complete_body_is_replayed_and_then_the_connection_heard(hook):
    status, received = _send_through_limit(
        [],
        [
            {"type": "http.request", "body": b"12", "more_body": True},
            {"type": "http.request", "body": b"34", "more_body": False},
        ],
        hook,
    )
    assert status is None
    assert received == [
        {"type": "http.request", "body": b"1234", "more_body": False},
        {"type": "http.disconnect"},
    ]


# -- allowances ---------------------------------------------------------------


def test_spending_an_allowance_counts_cost_until_the_window_ends(store):
    assert fixed_window_spend(store, "k", 6, 10, 60) == (True, 0)
    assert store.ttl("k") == 60
    allowed, retry = fixed_window_spend(store, "k", 6, 10, 60)
    assert not allowed and 0 < retry <= 60
    assert fixed_window_spend(store, "k", 1, 0, 60) == (True, 0)
    assert fixed_window_spend(store, "k", 1, 10, 0) == (True, 0)


def test_spending_against_an_unavailable_store_follows_the_callers_choice():
    class Down:
        def pipeline(self):
            raise ConnectionError("down")

    assert fixed_window_spend(Down(), "k", 1, 10, 60) == (True, 0)
    assert fixed_window_spend(Down(), "k", 1, 10, 60, fail_closed=True) == (False, 60)


# -- mailboxes ----------------------------------------------------------------


def test_a_mailbox_the_mail_library_reads_otherwise_is_refused(monkeypatch):
    assert email_address.single_mailbox("a@example.org") == "a@example.org"
    monkeypatch.setattr(
        email_address, "getaddresses", lambda values: [("a", "b@example.org")]
    )
    assert email_address.single_mailbox("a@example.org") is None


# -- the host binding ---------------------------------------------------------


def test_without_a_bound_application_the_hooks_keep_their_defaults(monkeypatch):
    monkeypatch.delitem(myf.host._bound, "hooks")
    assert hooks.session_allowed(None, None, {}) is True
    assert hooks.sso_identity_allowed("oidc", "i", "s") is None


def test_identity_is_needed_before_names_are_made(monkeypatch):
    monkeypatch.delitem(myf.host._identity, "name")
    with pytest.raises(RuntimeError, match="myf.host.bind"):
        myf.host.name()


# -- settings -----------------------------------------------------------------


def test_the_second_factor_policy_has_three_settings():
    assert Settings(mfa_policy="all").mfa_policy == "all"
    with pytest.raises(ValidationError, match="optional, admins or all"):
        Settings(mfa_policy="sometimes")


def test_a_public_address_with_a_malformed_port_is_refused():
    with pytest.raises(ValidationError, match="TESTAPP_PUBLIC_BASE_URL"):
        Settings(public_base_url="https://app.example:99999")


# -- the identity provider transport -------------------------------------------


def test_an_identity_provider_must_answer_without_compression(monkeypatch):
    closed = []

    class Compressed(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"x"

        async def aclose(self):
            closed.append(True)

    class Upstream:
        def __init__(self, **kwargs):
            pass

        async def handle_async_request(self, request):
            assert request.headers["Accept-Encoding"] == "identity"
            return httpx.Response(
                200, headers={"Content-Encoding": "gzip"}, stream=Compressed()
            )

    monkeypatch.setattr(sso_http.httpx, "AsyncHTTPTransport", Upstream)
    transport = sso_http.SsoTransport()

    async def fetch():
        request = httpx.Request("GET", "https://idp.example/.well-known/x")
        return await transport.handle_async_request(request)

    with pytest.raises(ValueError, match="Accept-Encoding: identity"):
        asyncio.run(fetch())
    assert closed == [True]


def test_a_sliding_window_admits_its_limit_in_any_window(store):
    from myf.security.rate_limit import sliding_window_allow

    def take(at):
        return sliding_window_allow(store, "costly", 2, 60, now=at)

    assert take(1000) == (True, 0)
    assert take(1030) == (True, 0)
    # A fixed window starting at 1000 would open again at 1060; this waits
    # until the first attempt leaves the window.
    assert take(1059) == (False, 1)
    assert take(1060.5) == (True, 0)
    assert take(1061) == (False, 29)
    assert store.zcard("costly") == 2
    assert sliding_window_allow(store, "free", 0, 60) == (True, 0)


def test_a_sliding_window_without_its_store_follows_the_callers_choice():
    from myf.security.rate_limit import sliding_window_allow

    class Down:
        def pipeline(self, transaction=True):
            raise ConnectionError("down")

    assert sliding_window_allow(Down(), "k", 1, 60) == (False, 60)
    assert sliding_window_allow(Down(), "k", 1, 60, fail_closed=False) == (True, 0)
