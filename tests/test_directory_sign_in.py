"""Signing in against an LDAP directory: its trust boundaries, group
requirements, and the accounts a directory identity reaches."""

import json
import logging
import re
import ssl
from http.cookies import SimpleCookie
from types import SimpleNamespace

import fakeredis
import pytest
from fastapi import HTTPException
from ldap3.core.exceptions import LDAPException
from ldap3.operation.bind import bind_operation
from starlette.requests import Request

import mosp.services.login as login_operations
from mosp.api.routes import auth
from mosp.api.schemas import LoginPayload
from mosp.security import ldap, mfa
from mosp.security.auth import authenticate_user
from mosp.security.auth import cookie_name as session_cookie_name
from mosp.security.sessions import get_session
from tests.ldap_directory import directory  # noqa: F401 - fixture
from tests.testapp.config import settings
from tests.testapp.models import MfaChallenge, User

LDAP_UNAVAILABLE = (
    "LDAP authentication unavailable; check directory configuration and connectivity"
)


def test_starttls_filter_escaping_and_ou(directory):
    state, events, connections = directory
    result = ldap.directory_identity("alice*)(uid=*)", "password")
    assert result["subject"] == "immutable-id"
    assert events[:3] == ["open", "tls", ("bind", "cn=reader,dc=example")]
    assert events[3:6] == ["open", "tls", ("bind", "uid=alice,ou=People,dc=example")]
    base, query, kw = state["search"]
    assert base == settings.ldap_base_dn and r"alice\2a\29\28uid=\2a\29" in query
    assert kw["size_limit"] == 2 and kw["dereference_aliases"] == ldap.DEREF_NEVER
    assert all(
        c.kw["auto_referrals"] is False and c.kw["read_only"] for c in connections
    )


def test_ldaps_cert_validation(directory, monkeypatch):
    monkeypatch.setattr(settings, "ldap_url", "ldaps://directory.example:636")
    real = ldap.Server
    seen = []
    monkeypatch.setattr(
        ldap, "Server", lambda *a, **kw: seen.append(kw) or real(*a, **kw)
    )
    assert ldap.directory_identity("alice", "secret") == {
        "issuer": "ldap:ldaps://directory.example:636",
        "subject": "immutable-id",
        "username": "alice",
        "email": "alice@example.org",
    }
    assert (seen[0]["use_ssl"], seen[0]["tls"].validate) == (True, ssl.CERT_REQUIRED)
    assert "tls" not in directory[1]


def test_failed_starttls_never_binds(directory):
    directory[0]["tls"] = False
    with pytest.raises(HTTPException) as error:
        ldap.directory_identity("alice", "secret")
    assert (error.value.status_code, error.value.detail) == (503, LDAP_UNAVAILABLE)
    assert directory[1] == ["open", "tls", "unbind"]


@pytest.mark.parametrize("case", ["ambiguous", "missing-id", "partial"])
def test_directory_denials(directory, case):
    state = directory[0]
    if case == "ambiguous":
        state["entries"] *= 2
    if case == "missing-id":
        state["entries"][0].entry_attributes_as_dict.pop("entryUUID")
    if case == "partial":
        state["result"] = 4
    assert ldap.directory_identity("alice", "secret") is None


@pytest.mark.parametrize(
    "changes",
    [
        {"ldap_url": "https://directory.example"},
        {"ldap_url": "ldap://"},
        {"ldap_url": "ldap://reader:secret@directory.example"},
        {"ldap_url": "ldap://directory.example/dc=example"},
        {"ldap_url": "ldap://directory.example?uid"},
        {"ldap_url": "ldap://directory.example#top"},
        {"ldap_base_dn": "   "},
        {"ldap_base_dn": "not a distinguished name"},
        {"ldap_username_attribute": "uid)(objectClass=*"},
        {"ldap_email_attribute": "mail;binary"},
        {"ldap_id_attribute": "1entryUUID"},
        {"ldap_bind_password": ""},
        {"ldap_bind_dn": ""},
    ],
    ids=[
        "scheme",
        "no-host",
        "embedded-credentials",
        "path",
        "query",
        "fragment",
        "blank-base",
        "malformed-base",
        "filter-in-attribute",
        "option-in-attribute",
        "attribute-digit",
        "dn-without-password",
        "password-without-dn",
    ],
)
def test_unsafe_directory_settings_refuse_sign_in_before_connecting(
    directory, monkeypatch, changes
):
    for key, value in changes.items():
        monkeypatch.setattr(settings, key, value)

    with pytest.raises(HTTPException) as error:
        ldap.directory_identity("alice", "secret")

    assert (error.value.status_code, error.value.detail) == (503, LDAP_UNAVAILABLE)
    assert directory[1] == []


POSIX_GROUPS = "(&(objectClass=posixGroup)(|(cn=staff)(cn=auditors)))"
GROUP = SimpleNamespace(entry_dn="cn=staff,ou=Groups,dc=example")


def test_without_a_group_filter_no_group_search_runs(directory):
    assert ldap.directory_identity("alice", "secret")["subject"] == "immutable-id"
    assert "group_search" not in directory[0]


def test_a_posix_group_member_signs_in_by_the_directory_username(
    directory, monkeypatch
):
    state, events, _ = directory
    monkeypatch.setattr(settings, "ldap_group_filter", POSIX_GROUPS)
    monkeypatch.setattr(settings, "ldap_group_member_attribute", "memberUid")
    state["groups"] = [GROUP]

    # memberUid matches exactly, so the directory's spelling is sent, not the typed one.
    assert ldap.directory_identity(" ALICE ", "secret")["username"] == "alice"

    base, query, kw = state["group_search"]
    assert base == settings.ldap_base_dn
    assert query == f"(&{POSIX_GROUPS}(memberUid=alice))"
    assert kw["size_limit"] == 1 and kw["dereference_aliases"] == ldap.DEREF_NEVER
    assert kw["time_limit"] == settings.ldap_timeout_seconds
    # Both searches use the service account, before the user's password is sent.
    assert state["searched_as"] == ["cn=reader,dc=example"] * 2
    assert events.count(("bind", "uid=alice,ou=People,dc=example")) == 1


def test_a_dn_valued_group_attribute_is_escaped_and_searched_below_its_own_base(
    directory, monkeypatch
):
    state = directory[0]
    monkeypatch.setattr(settings, "ldap_group_filter", "(objectClass=groupOfNames)")
    monkeypatch.setattr(settings, "ldap_group_base_dn", "ou=Groups,dc=example")
    state["entries"][0].entry_dn = "uid=al(ice)*,ou=People,dc=example"
    state["entries"][0].entry_attributes_as_dict["uid"] = ["al*)(cn=*"]
    state["groups"] = [GROUP]

    assert ldap.directory_identity("alice", "secret") is not None

    base, query, _ = state["group_search"]
    assert base == "ou=Groups,dc=example"
    assert query == (
        "(&(objectClass=groupOfNames)"
        r"(member=uid=al\28ice\29\2a,ou=People,dc=example))"
    )


def test_a_hostile_directory_username_cannot_widen_the_group_filter(
    directory, monkeypatch
):
    state = directory[0]
    monkeypatch.setattr(settings, "ldap_group_filter", POSIX_GROUPS)
    monkeypatch.setattr(settings, "ldap_group_member_attribute", "MemberUID")
    state["entries"][0].entry_attributes_as_dict["uid"] = ["al*)(cn=*"]
    state["groups"] = [GROUP]

    ldap.directory_identity("alice", "secret")

    assert state["group_search"][1] == (
        f"(&{POSIX_GROUPS}" r"(MemberUID=al\2a\29\28cn=\2a))"
    )


def test_someone_outside_the_groups_is_refused_before_their_password_is_tried(
    directory, db, monkeypatch
):
    state, events, _ = directory
    monkeypatch.setattr(settings, "ldap_group_filter", POSIX_GROUPS)
    monkeypatch.setattr(settings, "ldap_group_member_attribute", "memberUid")
    store = ldap.get_valkey()

    # The same answer as an unknown name: no account, no bind, no entry attempt.
    assert ldap.authenticate_ldap(db, "alice", "secret") is None
    assert db.query(User).count() == 0
    assert ("bind", "uid=alice,ou=People,dc=example") not in events
    assert store.keys("*") == []

    # Membership is read at each password check, so joining a group admits them
    # and leaving it refuses the next sign-in and reauthentication.
    state["groups"] = [GROUP]
    user = ldap.authenticate_ldap(db, "alice", "secret")
    assert user.username == "ldap:alice"
    assert ldap.verify_ldap_user(db, user, "secret") is True
    state["groups"] = []
    assert ldap.authenticate_ldap(db, "alice", "secret") is None
    assert ldap.verify_ldap_user(db, user, "secret") is False


def test_a_member_of_several_matching_groups_is_admitted(directory, monkeypatch):
    state = directory[0]
    monkeypatch.setattr(settings, "ldap_group_filter", POSIX_GROUPS)
    # The directory returns the first group and reports that more matched.
    state["groups"] = [GROUP]
    state["group_result"] = 4
    assert ldap.directory_identity("alice", "secret") is not None
    state["groups"] = []
    assert ldap.directory_identity("alice", "secret") is None


@pytest.mark.parametrize("result", [1, 10, 32, 50])
def test_a_group_search_the_directory_cannot_answer_is_not_a_refusal(
    directory, monkeypatch, result
):
    state, events, _ = directory
    monkeypatch.setattr(settings, "ldap_group_filter", POSIX_GROUPS)
    # A referral, a missing base or denied access says nothing about membership,
    # even when entries came back with it.
    state["groups"] = [GROUP]
    state["group_result"] = result
    with pytest.raises(HTTPException) as error:
        ldap.directory_identity("alice", "secret")
    assert (error.value.status_code, error.value.detail) == (503, LDAP_UNAVAILABLE)
    assert ("bind", "uid=alice,ou=People,dc=example") not in events


@pytest.mark.parametrize(
    "changes",
    [
        {"ldap_group_member_attribute": "member)(cn=*"},
        {"ldap_group_member_attribute": ""},
        {"ldap_group_base_dn": "not a distinguished name"},
    ],
    ids=["filter-in-attribute", "no-attribute", "malformed-group-base"],
)
def test_unsafe_group_settings_refuse_sign_in_before_connecting(
    directory, monkeypatch, changes
):
    monkeypatch.setattr(settings, "ldap_group_filter", POSIX_GROUPS)
    for key, value in changes.items():
        monkeypatch.setattr(settings, key, value)

    with pytest.raises(HTTPException) as error:
        ldap.directory_identity("alice", "secret")

    assert (error.value.status_code, error.value.detail) == (503, LDAP_UNAVAILABLE)
    assert directory[1] == []


def test_the_log_names_why_directory_sign_in_is_unavailable_without_directory_data(
    directory, monkeypatch, caplog
):
    caplog.set_level(logging.WARNING, logger="mosp.security.ldap")
    monkeypatch.setattr(settings, "ldap_bind_dn", "")
    with pytest.raises(HTTPException):
        ldap.directory_identity("alice", "secret")
    assert caplog.messages == [
        "LDAP sign-in unavailable: Supply both service bind DN and password"
    ]

    # A library or network failure may quote DNs, hosts or server diagnostics:
    # only its type is logged, and the response stays the fixed message.
    caplog.clear()
    monkeypatch.setattr(settings, "ldap_bind_dn", "cn=reader,dc=example")

    def failing_search(self, base, query, **kw):
        raise ldap.LDAPException(
            "uid=alice,ou=People,dc=example refused: synthetic-diagnostic"
        )

    monkeypatch.setattr(ldap.Connection, "search", failing_search)
    with pytest.raises(HTTPException) as error:
        ldap.directory_identity("alice", "secret")
    assert error.value.detail == LDAP_UNAVAILABLE
    assert caplog.messages == ["LDAP sign-in unavailable: LDAPException"]
    assert "alice" not in caplog.text and "synthetic-diagnostic" not in caplog.text
    assert "search-secret" not in caplog.text


@pytest.mark.parametrize("result", [49, 52])
def test_a_refused_service_bind_makes_directory_sign_in_unavailable(directory, result):
    directory[0]["service_bind"] = result
    with pytest.raises(HTTPException) as error:
        ldap.directory_identity("alice", "secret")
    assert (error.value.status_code, error.value.detail) == (503, LDAP_UNAVAILABLE)
    # The search never runs and the user's password is never sent.
    assert "search" not in directory[0]
    assert ("bind", "uid=alice,ou=People,dc=example") not in directory[1]


@pytest.mark.parametrize("result", [1, 51, 52, 80])
def test_a_directory_failure_during_the_user_bind_is_not_a_wrong_password(
    directory, result
):
    # A result that describes the directory, such as busy or unavailable,
    # means it could not answer.
    directory[0]["user_bind"] = result
    with pytest.raises(HTTPException) as error:
        ldap.directory_identity("alice", "secret")
    assert (error.value.status_code, error.value.detail) == (503, LDAP_UNAVAILABLE)
    directory[0]["user_bind"] = 49
    assert ldap.directory_identity("alice", "secret") is None


@pytest.mark.parametrize("result", sorted(ldap._ENTRY_REFUSALS))
def test_a_directory_refusing_one_entry_is_answered_as_a_wrong_password(
    directory, caplog, result
):
    """Directories refuse a locked, expired or disabled account with result
    codes of their own. Answered as an outage, they would show that the typed
    name matched an entry, which a wrong password never shows."""
    caplog.set_level("WARNING", logger="mosp.security.ldap")
    directory[0]["user_bind"] = result
    assert ldap.directory_identity("alice", "secret") is None
    # The operator's log names the code and nothing about the entry.
    assert caplog.messages == [f"LDAP sign-in bind refused with result code {result}"]
    assert "alice" not in caplog.text and "secret" not in caplog.text
    # The same code from the service account still means the directory is
    # misconfigured or unavailable.
    del directory[0]["user_bind"]
    directory[0]["service_bind"] = result
    with pytest.raises(HTTPException) as error:
        ldap.directory_identity("alice", "secret")
    assert error.value.status_code == 503


UNPREPARABLE = [
    "\u00ad",  # soft hyphen: prepared to nothing
    "\u200d\u200d",  # zero-width joiners: prepared to nothing
    "\t",  # a control character
    "\ufffd",  # what a NUL in a JSON body becomes
    "pass\ue000word",  # a private-use character
]


@pytest.mark.parametrize("password", UNPREPARABLE)
def test_ldap3_refuses_to_prepare_these_passwords_as_text(password):
    """The defect the next test guards against: ldap3 prepares a text password
    with SASLprep inside bind(), which TestApp reaches only for a name that
    matched an entry, and its refusal was answered as an outage (503) while
    every other name got a wrong password (401)."""
    with pytest.raises(LDAPException):
        bind_operation(3, ldap.SIMPLE, "uid=alice,ou=People,dc=example", password)


@pytest.mark.parametrize("password", UNPREPARABLE + ["pässword \u00a0\uff21"])
def test_every_name_gets_the_same_answer_whatever_the_password_holds(
    directory, monkeypatch, password
):
    state, events, connections = directory
    state["bind"] = False
    state["sent"] = []
    entry = ("bind", "uid=alice,ou=People,dc=example")

    # A name the directory holds: the password is sent as typed and refused.
    assert ldap.directory_identity("alice", password) is None
    assert events.count(entry) == 1
    assert state["sent"] == [b"search-secret", password.encode()]
    assert connections[-1].kw["password"] == password.encode()

    # A name it does not hold, and one outside the required group.
    state["entries"], kept = [], state["entries"]
    assert ldap.directory_identity("nobody", password) is None
    state["entries"] = kept
    monkeypatch.setattr(settings, "ldap_group_filter", "(objectClass=groupOfNames)")
    state["groups"] = []
    assert ldap.directory_identity("alice", password) is None
    assert events.count(entry) == 1

    # The right bytes still sign in.
    monkeypatch.setattr(settings, "ldap_group_filter", "")
    state["bind"] = True
    assert ldap.directory_identity("alice", password)["subject"] == "immutable-id"


def test_a_password_no_keyboard_can_type_is_refused_before_the_directory_is_asked(
    directory,
):
    _, events, _ = directory
    # A lone surrogate has no UTF-8 form.
    assert ldap.directory_identity("alice", "pass\ud800word") is None
    assert events == []


def test_directory_attributes_are_read_as_single_values_whatever_their_shape(
    directory,
):
    attributes = directory[0]["entries"][0].entry_attributes_as_dict
    attributes.update(uid="alice", mail=["alice@example.org"], entryUUID=[b"\x01\x02"])

    identity = ldap.directory_identity("alice", "secret")

    assert identity["username"] == "alice"
    # A binary identifier, such as objectGUID, is kept as base64 text.
    assert identity["subject"] == "AQI="
    attributes.update(uid=["alice", "alicia"])
    assert ldap.directory_identity("alice", "secret") is None


def test_a_new_directory_user_never_takes_an_existing_account_name(db, directory, hook):
    taken = User(username="ldap:alice", password_hash="local-hash", role="admin")
    db.add(taken)
    db.commit()
    created = []
    hook(user_created=lambda db, user: created.append(user.username))

    user = ldap.authenticate_ldap(db, "alice", "password")

    # The application is told of the new account before it is committed.
    assert created == [user.username]

    assert user.id != taken.id
    assert re.fullmatch("ldap:[0-9a-f]{32}", user.username)
    assert (user.role, user.auth_backend) == ("normal", "ldap")
    # The same directory identity returns to the same account afterwards.
    assert ldap.authenticate_ldap(db, "alice", "password").id == user.id
    assert created == [user.username]
    assert ldap.verify_ldap_user(db, taken, "password") is False


@pytest.mark.parametrize("name", ["ali\u202ece", "two\nlines"])
def test_a_directory_name_no_account_may_hold_gets_a_generated_one(
    db, directory, monkeypatch, name
):
    found = {
        "issuer": "ldap:ldap://directory.example",
        "subject": "immutable-id",
        "username": name,
        "email": None,
    }
    monkeypatch.setattr(ldap, "directory_identity", lambda *a, **kw: found)

    user = ldap.authenticate_ldap(db, "alice", "password")

    assert re.fullmatch("ldap:[0-9a-f]{32}", user.username)


def test_empty_password_never_connects(directory):
    assert ldap.directory_identity("alice", "") is None
    assert directory[1] == []


def test_directory_cannot_take_over_local_user(db, directory):
    admin = User(
        username="alice",
        email="alice@example.org",
        password_hash="local-hash",
        role="admin",
    )
    db.add(admin)
    db.commit()
    user = ldap.authenticate_ldap(db, "alice", "password")
    assert user.id != admin.id and user.role == "normal" and user.auth_backend == "ldap"
    assert user.password_hash == "!LDAP" and user.username == "ldap:alice"
    assert ldap.authenticate_ldap(db, "alice", "password").id == user.id
    assert authenticate_user(db, user.username, "password") is None
    user.is_active = False
    db.commit()
    assert ldap.authenticate_ldap(db, "alice", "password") is None


def test_no_auto_provision(db, directory, monkeypatch):
    monkeypatch.setattr(settings, "ldap_auto_provision", False)
    assert ldap.authenticate_ldap(db, "alice", "password") is None
    assert db.query(User).count() == 0


def test_reauthentication_requires_same_directory_identity(db, directory):
    user = ldap.authenticate_ldap(db, "alice", "password")
    assert ldap.verify_ldap_user(db, user, "password") is True
    directory[0]["entries"][0].entry_attributes_as_dict["entryUUID"] = ["different-id"]
    assert ldap.verify_ldap_user(db, user, "password") is False


def test_ldap_session_respects_mfa(db, directory, monkeypatch):
    user = ldap.authenticate_ldap(db, "alice", "password")
    user.mfa_enabled = True
    db.commit()
    monkeypatch.setattr(settings, "mfa_policy", "all")
    assert (
        mfa.local_session_allowed(
            db, user, {"auth_method": "ldap", "mfa_version": user.mfa_version}
        )
        is False
    )
    assert (
        mfa.local_session_allowed(
            db,
            user,
            {
                "auth_method": "ldap",
                "mfa_version": user.mfa_version,
                "mfa_verified": True,
            },
        )
        is True
    )
    assert not mfa.local_session_allowed(
        db,
        user,
        {
            "auth_method": "ldap",
            "mfa_version": user.mfa_version + 1,
            "mfa_verified": True,
        },
    )


def test_ldap_login_route_and_mfa_with_local_disabled(db, directory, monkeypatch):

    redis = fakeredis.FakeRedis()
    monkeypatch.setattr(login_operations, "get_valkey", lambda: redis)
    monkeypatch.setattr(auth, "get_valkey", lambda: redis)
    monkeypatch.setattr(settings, "local_auth_enabled", False)
    monkeypatch.setattr(settings, "mfa_policy", "off")
    monkeypatch.setattr(settings, "public_base_url", "https://app.example")
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "server": ("app.example", 443),
            "path": "/v1/auth/login",
            "query_string": b"",
            "headers": [(b"origin", b"https://app.example")],
            "client": ("192.0.2.1", 1000),
        }
    )
    response = auth.login(
        LoginPayload(username="alice", password="password", method="ldap"), request, db
    )
    assert (response.status_code, json.loads(response.body)) == (
        200,
        {"user": "ldap:alice", "user_id": str(db.query(User).one().id)},
    )

    cookie = SimpleCookie()
    for header in response.headers.getlist("set-cookie"):
        cookie.load(header)
    session = get_session(redis, cookie[session_cookie_name()].value)
    assert session["auth_method"] == "ldap"
    user = db.query(User).filter_by(auth_backend="ldap").one()
    user.mfa_enabled = True
    db.commit()
    response = auth.login(
        LoginPayload(username="alice", password="password", method="ldap"), request, db
    )
    assert json.loads(response.body)["mfa_required"] is True
    assert (
        db.query(MfaChallenge).filter_by(user_id=user.id, stage="verify").count() == 1
    )
    # With local sign-in off, a password sign-in that names no method is refused.
    with pytest.raises(HTTPException) as error:
        auth.login(LoginPayload(username="alice", password="password"), request, db)
    assert (error.value.status_code, error.value.detail) == (
        404,
        "Login method is disabled",
    )
