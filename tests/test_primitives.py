"""myf's stateless primitives, under a test application's name."""

import fakeredis
import pytest
from starlette.requests import Request

from myf.core.email_address import single_mailbox
from myf.core.identifiers import try_uuid
from myf.security import csrf, passwords, rate_limit, redaction, sessions
from myf.security.request_limits import screen_cookies, target_traverses
from myf.security.xml import parse_untrusted_xml


def test_store_keys_carry_the_application_name():
    store = fakeredis.FakeRedis(decode_responses=True)
    sid = sessions.create_session(store, user_id="u1", ttl_seconds=60)
    (key,) = store.keys("*")
    assert key.startswith("testapp:session:") and sid not in key
    assert sessions.get_session(store, sid)["user_id"] == "u1"
    rate_limit.address_window_allow(store, "probe", "2001:db8::1", 5, 60)
    assert "testapp:rl:probe:ip:2001:db8::/64" in store.keys("*")


@pytest.mark.parametrize(
    "address,allowance",
    [
        ("2001:db8::1", "2001:db8::/64"),
        ("2001:db8::ffff", "2001:db8::/64"),
        ("::ffff:192.0.2.7", "192.0.2.7"),
        ("192.0.2.7", "192.0.2.7"),
        ("not-an-address", None),
    ],
)
def test_an_ipv6_network_counts_as_one_address(address, allowance):
    assert rate_limit.address_allowance(address) == allowance


def _request(origin=None, fetch_site=None):
    headers = []
    if origin:
        headers.append((b"origin", origin.encode()))
    if fetch_site:
        headers.append((b"sec-fetch-site", fetch_site.encode()))
    return Request({"type": "http", "method": "POST", "headers": headers, "path": "/"})


@pytest.mark.parametrize(
    "origin,fetch_site,allowed",
    [
        ("https://app.example", None, True),
        ("https://app.example:443", None, True),
        ("https://evil.example", None, False),
        ("http://app.example", None, False),
        ("null", None, False),
        (None, None, True),
        (None, "cross-site", False),
    ],
)
def test_only_the_application_origin_may_write(origin, fetch_site, allowed):
    assert csrf.request_origin_allowed(_request(origin, fetch_site)) is allowed


def test_the_application_name_is_a_guessable_password():
    assert passwords.new_password_problem("testapp testapp testapp") is not None
    assert passwords.new_password_problem("testappadmin-2026-!!") is not None


def test_tokens_the_application_issues_are_redacted(hook):
    from tests.testapp.hooks import ISSUED

    text = "see https://app.example/x?next=tst_ABCDEFGH and tst_12345678"
    assert "tst_" in redaction.redact_str(text)
    hook(issued_secret_pattern=lambda: ISSUED)
    assert "tst_" not in redaction.redact_str(text)


def test_encoded_separators_reach_only_the_routes_that_take_them(hook):
    scope = {"path": "/v1/files/a/b", "raw_path": b"/v1/files/a%2Fb"}
    assert target_traverses(scope)
    assert target_traverses({"path": "/v1/../admin", "raw_path": b"/v1/../admin"})
    from myf.security.regex import scan_pattern

    hook(encoded_slash_routes=lambda: scan_pattern(r"/v1/files/.+"))
    assert not target_traverses(scope)


def test_cookie_names_outside_printable_ascii_are_dropped():
    scope = {"headers": [(b"cookie", b"a=1; \xa0__Host-testapp_session=x; b=2")]}
    screen_cookies(scope)
    assert scope["headers"] == [(b"cookie", b"a=1; b=2")]


def test_xml_with_entities_is_refused():
    with pytest.raises(Exception):
        parse_untrusted_xml(b'<!DOCTYPE a [<!ENTITY e "x">]><a>&e;</a>')
    assert parse_untrusted_xml(b"<a><b/></a>").tag == "a"


def test_identifiers_and_mailboxes_have_one_spelling():
    assert try_uuid("8b0c3f8e-5d2a-4c61-9a57-2f0b7e3d1c44") is not None
    assert try_uuid("{8b0c3f8e-5d2a-4c61-9a57-2f0b7e3d1c44}") is None
    assert single_mailbox("Someone <a@example.com>") is None
    assert single_mailbox(" a@example.com ") == "a@example.com"


def test_iso_times_have_one_reading():
    from datetime import datetime

    from myf.core.datetime_utils import parse_iso_datetime, parse_iso_datetime_or_none

    assert parse_iso_datetime("2026-01-07T00:09:08Z") == datetime(2026, 1, 7, 0, 9, 8)
    assert parse_iso_datetime("2026-01-01T10:00+10:00") == datetime(2026, 1, 1)
    assert parse_iso_datetime(" 2026-01-01T00:00:00.1234567Z ") == datetime(
        2026, 1, 1, 0, 0, 0, 123456
    )
    assert parse_iso_datetime("2026-01-01 10:00") == datetime(2026, 1, 1, 10)
    with pytest.raises(ValueError, match="timezone"):
        parse_iso_datetime("2026-01-01T10:00", require_timezone=True)
    with pytest.raises(ValueError, match="out of range"):
        parse_iso_datetime("0001-01-01T00:00+01:00")
    with pytest.raises(ValueError):
        parse_iso_datetime("yesterday")
    assert parse_iso_datetime_or_none("yesterday") is None
    assert parse_iso_datetime_or_none(12) is None
    assert parse_iso_datetime_or_none("  ") is None
    assert parse_iso_datetime_or_none("2026-01-01T00:00Z") == datetime(2026, 1, 1)
