"""Sign-in and sign-out routes, sessions, second factors and security notices
along the paths the other suites leave out."""

import uuid

import fakeredis
import pytest
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from starlette.requests import Request

from myf import middleware
from myf.api.routes import auth as auth_routes
from myf.api.schemas import LoginPayload
from myf.security import ldap, sessions
from myf.security.auth import cookie_name as session_cookie_name
from myf.services import login, security_notifications
from tests.assembled import BASE, PASSWORD, unsafe
from tests.ldap_directory import directory  # noqa: F401 - fixture
from tests.testapp.config import settings
from tests.testapp.models import AuditLog, SecurityNotification, User

# -- signing in and out -------------------------------------------------------


def test_a_sign_in_from_another_origin_is_refused(site):
    user = site.user()
    refused = site.client().post(
        "/v1/auth/login",
        json={"username": user.username, "password": PASSWORD},
        headers={"Origin": "https://elsewhere.example"},
    )
    assert (refused.status_code, refused.json()) == (
        403,
        {"detail": "Authentication request origin is not allowed"},
    )


def test_the_sign_in_route_checks_the_origin_itself(db):
    # Mounted without myf's middleware, the route still refuses.
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "server": ("app.example", 443),
            "path": "/v1/auth/login",
            "query_string": b"",
            "headers": [(b"origin", b"https://elsewhere.example")],
            "client": ("192.0.2.1", 1000),
        }
    )
    with pytest.raises(HTTPException) as refused:
        auth_routes.login(LoginPayload(username="a", password="b"), request, db)
    assert (refused.value.status_code, refused.value.detail) == (
        403,
        "Authentication request origin is not allowed",
    )


def test_signing_in_again_replaces_the_browsers_session_even_if_the_old_one_lingers(
    site, monkeypatch
):
    user = site.user()
    client = site.client(user)
    first = client.cookies.get(session_cookie_name())

    def unavailable(store, sid):
        raise ConnectionError("store refused")

    monkeypatch.setattr(login, "delete_session", unavailable)
    again = client.post(
        "/v1/auth/login",
        json={"username": user.username, "password": PASSWORD},
        headers={"Origin": BASE},
    )
    assert again.status_code == 200
    assert client.cookies.get(session_cookie_name()) != first


def test_a_sign_out_the_store_cannot_record_keeps_the_browsers_cookies(
    site, monkeypatch
):
    client = site.client(site.user())

    def unavailable(store, sid):
        raise ConnectionError("store refused")

    monkeypatch.setattr(auth_routes, "revoke_session", unavailable)
    response = client.post("/v1/auth/logout", headers=unsafe(client))
    assert (response.status_code, response.json()) == (
        503,
        {"detail": "Sign-out could not be completed; try again"},
    )
    assert "set-cookie" not in response.headers


@pytest.mark.parametrize("path", ["/v1/auth/logout", "/v1/auth/oidc/logout"])
def test_a_followed_sign_out_link_leads_to_the_account_page(site, path):
    response = site.client().get(path, follow_redirects=False)
    assert (response.status_code, response.headers["location"]) == (
        303,
        "/account.html",
    )


def test_the_administrator_check_names_the_account(site):
    admin = site.client(site.user(role="admin"))
    response = admin.get("/v1/auth/check-admin")
    assert response.status_code == 204
    assert response.headers["x-testapp-role"] == "admin"
    assert site.client(site.user()).get("/v1/auth/check-admin").status_code == 403


def test_a_session_from_before_a_factor_change_signs_nobody_in(production_client):
    client, redis, admin, reader = production_client
    sid = sessions.create_session(
        redis, user_id=str(reader.id), ttl_seconds=300, mfa_version=99
    )
    client.cookies.set(session_cookie_name(), sid)
    assert client.get("/v1/auth/check").status_code == 401
    assert sessions.get_session(redis, sid) is None


def test_a_session_read_against_its_lifetime_alone_keeps_its_ttl():
    store = fakeredis.FakeRedis(decode_responses=True)
    sid = sessions.create_session(store, user_id="u", ttl_seconds=600)
    assert sessions.get_session(store, sid, max_age_seconds=6000)["user_id"] == "u"
    assert 590 < store.ttl(sessions.session_key(sid)) <= 600


# -- requests the application authenticates itself ----------------------------


def test_the_application_may_answer_or_name_the_account_for_its_own_requests(
    site, hook
):
    admin = site.user(role="admin")

    def inner(db, request):
        if request.url.path == "/v1/things":
            return JSONResponse({"detail": "Machine key refused"}, status_code=401)
        return db.get(User, admin.id)

    hook(inner_request_user=inner)
    client = site.client()
    refused = client.get("/v1/things")
    assert (refused.status_code, refused.json()) == (
        401,
        {"detail": "Machine key refused"},
    )
    assert client.get("/v1/admin/overview").json() == {"admin": True}


def test_anonymous_requests_past_their_allowance_are_not_recorded(site, monkeypatch):
    monkeypatch.setattr(middleware, "ANONYMOUS_AUDIT_LIMIT", 1)
    client = site.client()
    for _ in range(3):
        client.get("/v1/things")
    site.db.expire_all()
    assert site.db.query(AuditLog).filter_by(path="/v1/things").count() == 1


# -- second factors -----------------------------------------------------------


def test_an_account_reads_its_second_factor_status(site, monkeypatch):
    monkeypatch.setattr(settings, "mfa_policy", "optional")
    client = site.client(site.user())
    assert client.get("/v1/me/mfa").json() == {
        "enabled": False,
        "totp": False,
        "credentials": [],
        "recovery_codes_remaining": 0,
        "policy": "optional",
        "required": False,
        "local_enabled": True,
    }


# -- directory accounts -------------------------------------------------------


def test_a_directory_account_created_concurrently_asks_for_a_new_sign_in(
    db, directory, hook
):
    def concurrently(db, user):
        raise IntegrityError("INSERT", {}, Exception("duplicate"))

    hook(user_created=concurrently)
    with pytest.raises(HTTPException) as refused:
        ldap.authenticate_ldap(db, "alice", "password")
    assert (refused.value.status_code, refused.value.detail) == (
        409,
        "Account was created concurrently; please sign in again",
    )
    assert db.query(User).count() == 0


# -- security notices ---------------------------------------------------------


@pytest.fixture
def mail(db, monkeypatch):
    monkeypatch.setattr(settings, "smtp_host", "smtp.example")
    monkeypatch.setattr(settings, "smtp_from_email", "app@example.org")
    user = User(
        username="noticed",
        email="noticed@example.org",
        password_hash="x",
        role="normal",
    )
    db.add(user)
    db.flush()
    return db, user


def test_the_application_writes_its_own_notices(mail, hook):
    db, user = mail
    hook(
        security_notice=lambda event: (
            ("Your report was exported", "Ask if not you.")
            if event == "report-exported"
            else None
        )
    )
    security_notifications.enqueue(db, user, "report-exported", ip="203.0.113.7")
    security_notifications.enqueue(db, user, "password-changed")
    db.flush()

    assert security_notifications.pending_for(db, user.id) == 2
    # Looked up by subject: how the database orders text depends on its
    # collation.
    notices = {n.subject: n for n in db.query(SecurityNotification).all()}
    own = notices["TestApp security: Your report was exported"]
    standard = notices["TestApp security: Your TestApp password was changed"]
    assert "IP address: 203.0.113.7" in own.body and "Ask if not you." in own.body
    assert "Unavailable (operator action or unknown address)" in standard.body


def test_nothing_is_pending_for_an_account_never_written_to(db):
    assert security_notifications.pending_for(db, uuid.uuid4()) == 0


def test_a_provider_session_lasts_only_while_the_provider_is_enabled(
    production_client, monkeypatch
):
    client, redis, admin, reader = production_client

    def signed_in(method):
        sid = sessions.create_session(
            redis, user_id=str(reader.id), ttl_seconds=300, auth_method=method
        )
        client.cookies.set(session_cookie_name(), sid)
        return sid

    monkeypatch.setattr(settings, "oidc_enabled", True)
    signed_in("oidc")
    assert client.get("/v1/auth/check").status_code == 204

    monkeypatch.setattr(settings, "oidc_enabled", False)
    assert client.get("/v1/auth/check").status_code == 401
    # Turning the provider back on does not bring the session back.
    monkeypatch.setattr(settings, "oidc_enabled", True)
    assert client.get("/v1/auth/check").status_code == 401
    # A method no provider answers to signs nobody in.
    signed_in("retired-provider")
    assert client.get("/v1/auth/check").status_code == 401
