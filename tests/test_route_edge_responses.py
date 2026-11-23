"""Edge responses of the sign-in, sign-out and factor-management routes.

Requests pass through the assembled application: real password sign-in,
CSRF, session storage and permission resolution. The directory is replaced at
its network boundary and the session store is the fixture's in-memory Valkey.
"""

import json
from urllib.parse import urlencode

from mosp.api.routes import auth as auth_routes
from mosp.security import ldap
from mosp.security.auth import cookie_name as session_cookie_name
from mosp.security.passwords import hash_password
from mosp.security.sessions import create_session, session_key

# Imported fixture: the assembled application with an in-memory session store.
from tests.assembled import BASE, PASSWORD, unsafe
from tests.testapp.config import settings
from tests.testapp.models import User, UserIdentity

# --- Sign-in allowances -------------------------------------------------------------


def test_a_zero_address_allowance_leaves_only_the_account_throttle(
    site,
    monkeypatch,
):
    monkeypatch.setattr(settings, "login_rate_limit_per_ip", 0)
    client = site.client()

    def attempt(username):
        return client.post(
            "/v1/auth/login",
            json={"username": username, "password": "not-the-password"},
            headers={"Origin": BASE},
        ).status_code

    # One address may try any number of usernames, each under its own
    # throttle: five free failures, then a wait before the next is heard.
    assert [attempt(f"someone-{n}") for n in range(4)] == [401] * 4
    assert [attempt("someone-0") for _ in range(5)] == [401] * 5
    assert attempt("someone-0") == 429
    assert attempt("someone-1") == 401

    # An address allowance of one refuses the address's second attempt.
    monkeypatch.setattr(settings, "login_rate_limit_per_ip", 1)
    assert [attempt("another-1"), attempt("another-2")] == [401, 429]


# --- Signing out through the identity provider --------------------------------------


def _oidc_session(app, client, id_token):
    # A provider session signs in only while its provider is enabled.
    app.monkeypatch.setattr(settings, "oidc_enabled", True)
    sid = client.cookies.get(session_cookie_name())
    key = session_key(sid)
    payload = json.loads(app.store.get(key))
    payload.update(auth_method="oidc", oidc_id_token=id_token)
    app.store.set(key, json.dumps(payload), keepttl=True)
    return sid


def test_signing_out_of_a_provider_session_names_the_providers_sign_out(
    site,
    monkeypatch,
):
    end_session = "https://sso.example.test/logout"
    after = BASE + "/login.html"
    monkeypatch.setattr(settings, "oidc_end_session_endpoint", end_session)
    monkeypatch.setattr(settings, "oidc_post_logout_redirect_uri", after)
    client = site.client(site.user())
    sid = _oidc_session(site, client, "synthetic.id.token")

    response = client.post("/v1/auth/oidc/logout", headers=unsafe(client))

    assert response.status_code == 200, response.text
    query = urlencode(
        {"id_token_hint": "synthetic.id.token", "post_logout_redirect_uri": after},
        safe=":/?&=",
    )
    assert response.json() == {"logout_url": f"{end_session}?{query}"}
    replay = site.client()
    replay.cookies.set(session_cookie_name(), sid)
    refused = replay.get("/v1/me")
    assert (refused.status_code, refused.json()) == (
        401,
        {"detail": "Not authenticated"},
    )

    # A session without an ID token returns to the provider's sign-out address.
    plain = site.client(site.user())
    _oidc_session(site, plain, "")
    assert plain.post("/v1/auth/oidc/logout", headers=unsafe(plain)).json() == {
        "logout_url": after
    }


def test_provider_sign_out_fails_closed_when_the_session_cannot_be_read(
    site,
    monkeypatch,
):
    client = site.client(site.user())
    sid = _oidc_session(site, client, "synthetic.id.token")

    def unavailable(store, session_id):
        raise ConnectionError("session store down")

    with monkeypatch.context() as patch:
        patch.setattr(auth_routes, "get_session", unavailable)
        failed = client.post("/v1/auth/oidc/logout", headers=unsafe(client))

    assert failed.status_code == 503
    assert failed.json()["detail"] == "Sign-out could not be completed; try again"
    assert failed.headers["retry-after"] == "5"
    assert failed.headers["cache-control"] == "no-store"
    assert session_cookie_name() not in failed.headers.get("set-cookie", "")
    assert client.cookies.get(session_cookie_name()) == sid
    assert client.get("/v1/me").status_code == 200


# --- Factor management for directory accounts ---------------------------------------


def test_directory_accounts_confirm_factor_management_with_the_directory(
    site,
    monkeypatch,
):
    user = site.user()
    user.auth_backend = "ldap"
    user.password_hash = hash_password(PASSWORD)
    site.db.add(
        UserIdentity(
            user_id=user.id,
            provider="ldap",
            issuer="ldap://directory.example.test",
            subject="uid=synthetic",
            preferred_username=user.username,
        )
    )
    site.db.commit()
    asked = []

    def directory(username, password):
        asked.append((username, password))
        if password != "directory-password":
            return None
        return {"issuer": "ldap://directory.example.test", "subject": "uid=synthetic"}

    monkeypatch.setattr(ldap, "directory_identity", directory)
    client = site.client()
    client.cookies.set(
        session_cookie_name(),
        create_session(
            site.store,
            user_id=str(user.id),
            ttl_seconds=settings.session_ttl_seconds,
            auth_method="ldap",
        ),
    )

    def start(password):
        return client.post(
            "/v1/auth/mfa/manage/start",
            json={"password": password},
            headers={"Origin": BASE},
        )

    # The account's local password hash is never consulted.
    refused = start(PASSWORD)
    assert (refused.status_code, refused.json()["detail"]) == (401, "Invalid password")
    started = start("directory-password")
    assert (started.status_code, started.json()) == (
        200,
        {"mfa_required": True, "next": "/mfa.html"},
    )
    assert asked == [
        (user.username, PASSWORD),
        (user.username, "directory-password"),
    ]
    assert site.db.get(User, user.id).auth_backend == "ldap"
