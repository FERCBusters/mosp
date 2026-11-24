"""An account changing its own password."""

import pytest

from mosp.security import sign_in_throttle as throttle
from mosp.services import account
from tests.assembled import BASE, PASSWORD, unsafe
from tests.testapp.config import settings
from tests.testapp.models import SecurityNotification, User

NEW = "another-synthetic-passphrase"


def _change(client, current, new=NEW):
    response = client.post(
        "/v1/me/password",
        headers=unsafe(client),
        json={"current_password": current, "new_password": new},
    )
    return response.status_code, response.json()


def test_a_change_checks_the_current_password_and_ends_other_sessions(
    site, monkeypatch
):
    monkeypatch.setattr(settings, "smtp_host", "smtp.example")
    monkeypatch.setattr(settings, "smtp_from_email", "app@example.org")
    user = site.user()
    user.email = "owner@example.org"
    site.db.commit()
    client = site.client(user)

    assert _change(client, "not-it") == (
        400,
        {"detail": "Current password is incorrect"},
    )
    assert _change(client, PASSWORD, "x") == (
        400,
        {"detail": "Password must be at least 15 characters"},
    )
    # A long one is refused by the same rules, with their message.
    assert _change(client, PASSWORD, "x" * 1025) == (
        400,
        {"detail": "Password must be at most 1024 characters"},
    )
    before = site.db.get(User, user.id).mfa_version
    assert _change(client, PASSWORD) == (200, {"ok": True})

    site.db.expire_all()
    assert site.db.get(User, user.id).mfa_version == before + 1
    # The session the change came from no longer authenticates.
    assert client.get("/v1/auth/check").status_code == 401
    login = site.client().post(
        "/v1/auth/login",
        json={"username": user.username, "password": NEW},
        headers={"Origin": BASE},
    )
    assert login.status_code == 200
    (notice,) = site.db.query(SecurityNotification).all()
    assert notice.subject == "TestApp security: Your TestApp password was changed"


def test_directory_and_proxy_accounts_change_their_password_elsewhere(
    site, monkeypatch
):
    user = site.user()
    client = site.client(user)
    row = site.db.get(User, user.id)
    row.auth_backend = "ldap"
    site.db.commit()
    assert _change(client, PASSWORD) == (
        403,
        {"detail": "Change your password in your LDAP directory"},
    )
    row.auth_backend = "local"
    site.db.commit()
    monkeypatch.setattr(settings, "trust_remote_user", True)
    assert _change(client, PASSWORD) == (
        403,
        {
            "detail": "Password changes are disabled when"
            " TESTAPP_TRUST_REMOTE_USER is enabled"
        },
    )


def test_attempts_are_limited_for_each_account_and_address(site, monkeypatch):
    monkeypatch.setattr(settings, "login_rate_limit_per_ip", 100)
    monkeypatch.setattr(settings, "password_change_rate_limit_per_account", 2)
    user = site.user()
    client = site.client(user)
    original = user.password_hash

    assert [_change(client, "wrong") for _ in range(2)] == [
        (400, {"detail": "Current password is incorrect"})
    ] * 2
    # Once the account's allowance is spent, the right password is refused
    # before it is checked too, so guesses cannot continue from new addresses.
    limited = (
        429,
        {"detail": "Too many password change attempts. Please try again later."},
    )
    assert _change(client, PASSWORD) == limited
    site.db.refresh(user)
    assert user.password_hash == original

    monkeypatch.setattr(settings, "password_change_rate_limit_per_account", 100)
    # Only the two attempts the account admitted were charged to the address;
    # past the address's own allowance a change is refused too, and the
    # account has that attempt back.
    monkeypatch.setattr(settings, "login_rate_limit_per_ip", 2)
    assert _change(client, PASSWORD) == limited
    assert site.store.zcard(f"testapp:rl:password_change:account:{user.id}") == 2


def test_one_account_cannot_spend_its_addresss_allowance_for_others(site, monkeypatch):
    monkeypatch.setattr(settings, "login_rate_limit_per_ip", 4)
    monkeypatch.setattr(settings, "password_change_rate_limit_per_account", 2)
    busy, neighbour = site.user(), site.user()
    client = site.client(busy)
    for _ in range(6):
        _change(client, "wrong")
    # The busy account's refused attempts left the address with two.
    other = site.client(neighbour)
    assert _change(other, "wrong") == (
        400,
        {"detail": "Current password is incorrect"},
    )


def test_without_the_store_no_change_is_attempted(site, monkeypatch):
    client = site.client(site.user())

    def unavailable():
        raise ConnectionError("store refused")

    monkeypatch.setattr(account, "get_valkey", unavailable)
    assert _change(client, PASSWORD) == (
        503,
        {"detail": "Service temporarily unavailable. Please try again later."},
    )


def test_a_change_ends_sessions_opened_through_sso(site, monkeypatch):
    from mosp.core.valkey import get_valkey
    from mosp.security.auth import cookie_name
    from mosp.security.sessions import create_session

    monkeypatch.setattr(settings, "oidc_enabled", True)
    user = site.user()
    client = site.client(user)
    sso = site.client()
    sso.cookies.set(
        cookie_name(),
        create_session(
            get_valkey(),
            user_id=str(user.id),
            ttl_seconds=600,
            auth_method="oidc",
            session_version=user.session_version,
        ),
    )
    assert sso.get("/v1/auth/check").status_code == 204

    assert _change(client, PASSWORD) == (200, {"ok": True})
    assert sso.get("/v1/auth/check").status_code == 401


def test_a_new_password_ends_every_browsers_recognition(site, monkeypatch):
    revoked, cleared = [], []
    monkeypatch.setattr(
        throttle, "revoke_account_devices", lambda r, user_id: revoked.append(user_id)
    )
    monkeypatch.setattr(throttle, "clear_throttle", lambda r, key: cleared.append(key))

    account.end_password_recognition("u1")
    account.end_password_recognition("u2", key="name-key")
    assert (revoked, cleared) == (["u1", "u2"], ["name-key"])

    def unavailable():
        raise ConnectionError("store refused")

    monkeypatch.setattr(account, "get_valkey", unavailable)
    assert account.end_password_recognition("u3") is None


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
def test_only_a_post_changes_a_password(site, method):
    client = site.client(site.user())
    response = client.request(method, "/v1/me/password", headers=unsafe(client))
    assert response.status_code == 405
