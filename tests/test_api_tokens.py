"""API tokens: issued by administrators for one account, verified by the
middleware for the reads the route policy lists, and refused everywhere else."""

from __future__ import annotations

import subprocess
import sys
import uuid
from datetime import timedelta

import pytest

from mosp.core.datetime_utils import utc_now_naive
from mosp.security import api_token_format, api_tokens, redaction
from mosp.security.route_policy import MOSP_POLICY, RoutePolicy, RouteSet
from mosp.services import security_notifications
from tests.assembled import PASSWORD, unsafe
from tests.testapp import models as testapp_models
from tests.testapp.models import ApiToken, AuditLog, SecurityNotification, User


@pytest.fixture(autouse=True)
def tokens_on(monkeypatch):
    """The installation turns API tokens on (they are off by default)."""
    from tests.testapp.config import settings

    monkeypatch.setattr(settings, "api_tokens_enabled", True)
    return settings


def _issue(site, user, *, admin=None, **fields):
    admin_client = site.client(admin or site.user(role="admin"))
    response = admin_client.post(
        "/v1/admin/api-tokens",
        json={"name": "keen reader", "user_id": str(user.id), **fields},
        headers=unsafe(admin_client),
    )
    assert response.status_code == 201, response.text
    return response.json()


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _token_for(site, *codes, role="normal", **fields):
    user = site.user(*codes, role=role)
    return user, _issue(site, user, **fields)["token"]


def test_an_issued_token_reads_the_listed_routes_as_its_account(site):
    user, token = _token_for(site)
    assert token.startswith("testapp_at_")
    assert api_token_format.pattern().fullmatch(token)
    response = site.client().get("/v1/things", headers=_bearer(token))
    assert response.status_code == 200
    assert response.json() == {"user": user.username}
    # A token request is not a browser's: it is given no CSRF cookie.
    assert "__Host-testapp_csrf" not in response.cookies
    # Only the digest is kept.
    (row,) = site.db.query(ApiToken).all()
    assert row.token_hash == api_token_format.digest(token)
    assert row.hint == token[-4:]
    assert token not in {row.token_hash, row.hint, row.name}


def test_a_token_reaches_no_route_the_policy_does_not_list(site):
    _, token = _token_for(site, role="admin")
    anonymous = site.client()
    unlisted = anonymous.get("/v1/me", headers=_bearer(token))
    assert unlisted.status_code == 403
    assert unlisted.json() == {
        "detail": "API tokens reach only the routes listed for them"
    }
    # Writes are refused before any route runs, CSRF or not, administrator or not.
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        response = anonymous.request(
            method, "/v1/things", headers={**_bearer(token), "Origin": BASE_ORIGIN}
        )
        assert response.status_code == 403, method
    # The administration namespace stays closed to tokens.
    assert (
        anonymous.get("/v1/admin/api-tokens", headers=_bearer(token)).status_code == 403
    )


BASE_ORIGIN = "https://app.example"
NEW_PASSWORD = "another-synthetic-passphrase-for-tests"


def test_head_requests_count_as_reads(site):
    _, token = _token_for(site)
    # The middleware admits it; the router, which serves no HEAD, answers.
    assert site.client().head("/v1/things", headers=_bearer(token)).status_code == 405


@pytest.mark.parametrize(
    "credential",
    [
        "testapp_at_short",
        "testapp_at_" + "x" * 43 + "!",
        "testapp_at_" + "a" * 43,  # well formed, never issued
    ],
)
def test_unusable_tokens_are_refused_alike(site, credential):
    response = site.client().get("/v1/things", headers=_bearer(credential))
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}
    assert response.headers["WWW-Authenticate"] == 'Bearer error="invalid_token"'


def test_revoked_expired_and_inactive_tokens_are_refused(site):
    reader = site.client()
    user, token = _token_for(site)
    row = site.db.query(ApiToken).one()

    row.expires_at = utc_now_naive() - timedelta(seconds=1)
    site.db.commit()
    assert reader.get("/v1/things", headers=_bearer(token)).status_code == 401

    row.expires_at = utc_now_naive() + timedelta(days=1)
    site.db.commit()
    assert reader.get("/v1/things", headers=_bearer(token)).status_code == 200

    account = site.db.get(User, user.id)
    account.is_active = False
    site.db.commit()
    assert reader.get("/v1/things", headers=_bearer(token)).status_code == 401

    account.is_active = True
    row.revoked_at = utc_now_naive()
    site.db.commit()
    assert reader.get("/v1/things", headers=_bearer(token)).status_code == 401


def test_the_accounts_own_credential_changes_leave_its_tokens_working(site):
    admin = site.user(role="admin")
    user, token = _token_for(site, admin=admin)
    reader = site.client()
    # The account changes its password, which ends every session of it.
    browser = site.client(user)
    changed = browser.post(
        "/v1/me/password",
        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
        headers=unsafe(browser),
    )
    assert changed.status_code == 200, changed.text
    assert browser.get("/v1/me").status_code == 401
    # The token is a credential of its own: revoking or expiring it ends it.
    assert reader.get("/v1/things", headers=_bearer(token)).status_code == 200
    listing = site.client(admin).get("/v1/admin/api-tokens").json()["items"]
    assert [row["status"] for row in listing] == ["active"]


def test_deactivating_an_account_revokes_its_tokens_for_good(site):
    from mosp.services import api_tokens as service

    admin = site.user(role="admin")
    user, token = _token_for(site, admin=admin)
    _, other = _token_for(site, admin=admin)
    reader = site.client()
    account = site.db.get(User, user.id)
    # What an application's deactivation does, in one transaction.
    account.is_active = False
    assert service.revoke_for_account(site.db, account) == 1
    site.db.commit()
    assert reader.get("/v1/things", headers=_bearer(token)).status_code == 401
    account.is_active = True
    site.db.commit()
    assert reader.get("/v1/things", headers=_bearer(token)).status_code == 401
    statuses = {
        row["username"]: row["status"]
        for row in site.client(admin).get("/v1/admin/api-tokens").json()["items"]
    }
    assert statuses[user.username] == "revoked"
    # Another account's token is untouched, and the account can be issued a
    # new one.
    assert reader.get("/v1/things", headers=_bearer(other)).status_code == 200
    fresh = _issue(site, user, admin=admin)["token"]
    assert reader.get("/v1/things", headers=_bearer(fresh)).status_code == 200
    # Revoked tokens are not revoked again.
    assert service.revoke_for_account(site.db, account) == 1


def test_an_inactive_accounts_tokens_are_refused_and_listed_as_inactive(site):
    admin = site.user(role="admin")
    user, token = _token_for(site, admin=admin)
    site.db.get(User, user.id).is_active = False
    site.db.commit()
    assert site.client().get("/v1/things", headers=_bearer(token)).status_code == 401
    listing = site.client(admin).get("/v1/admin/api-tokens").json()["items"]
    assert [row["status"] for row in listing] == ["inactive"]


def test_a_token_decides_alone_when_a_session_is_also_present(site):
    admin = site.user(role="admin")
    user, token = _token_for(site, admin=admin)
    browser = site.client(admin)
    # Signed in as the administrator, the request still acts as the token's
    # account, and only where tokens reach.
    assert browser.get("/v1/things", headers=_bearer(token)).json() == {
        "user": user.username
    }
    assert browser.get("/v1/me", headers=_bearer(token)).status_code == 403
    assert browser.get("/v1/me").json() == {"user": admin.username}


def test_another_kind_of_bearer_credential_is_left_to_the_session(site):
    admin = site.user(role="admin")
    browser = site.client(admin)
    other = {"Authorization": "Bearer someone-elses-token"}
    assert browser.get("/v1/me", headers=other).json() == {"user": admin.username}
    assert site.client().get("/v1/me", headers=other).status_code == 401


def test_a_duplicated_authorization_header_is_refused(site):
    _, token = _token_for(site)
    client = site.client()
    for headers in (
        [("Authorization", f"Bearer {token}"), ("Authorization", f"Bearer {token}")],
        [("Authorization", f"Bearer {token}"), ("Authorization", "Basic eDp5")],
    ):
        response = client.get("/v1/things", headers=headers)
        assert response.status_code == 401


def test_each_token_has_its_own_allowance(site, monkeypatch):
    monkeypatch.setattr(api_tokens, "READS_PER_MINUTE", 1)
    _, first = _token_for(site)
    _, second = _token_for(site)
    client = site.client()
    assert client.get("/v1/things", headers=_bearer(first)).status_code == 200
    limited = client.get("/v1/things", headers=_bearer(first))
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) > 0
    assert client.get("/v1/things", headers=_bearer(second)).status_code == 200


def test_last_use_is_written_at_most_once_a_minute(site):
    _, token = _token_for(site)
    client = site.client()
    row = site.db.query(ApiToken).one()
    assert row.last_used_at is None
    client.get("/v1/things", headers=_bearer(token))
    site.db.refresh(row)
    first = row.last_used_at
    assert first is not None
    client.get("/v1/things", headers=_bearer(token))
    site.db.refresh(row)
    assert row.last_used_at == first
    row.last_used_at = first - timedelta(minutes=2)
    site.db.commit()
    client.get("/v1/things", headers=_bearer(token))
    site.db.refresh(row)
    assert row.last_used_at > first - timedelta(minutes=2)


def test_token_requests_are_audited_under_the_account(site):
    user, token = _token_for(site)
    site.client().get("/v1/things?key=value", headers=_bearer(token))
    record = (
        site.db.query(AuditLog)
        .filter(AuditLog.path == "/v1/things", AuditLog.username == user.username)
        .one()
    )
    assert record.status_code == 200


def test_without_the_model_bearer_tokens_are_not_read(site, monkeypatch):
    user, token = _token_for(site)
    monkeypatch.delattr(testapp_models, "ApiToken")
    assert api_tokens.enabled() is False
    assert site.client().get("/v1/things", headers=_bearer(token)).status_code == 401


def test_tokens_are_redacted_wherever_redaction_applies():
    token = "testapp_at_" + "Z" * 43
    assert redaction.redact_str(f"sent {token} upstream") == "sent REDACTED upstream"


def test_redaction_still_loads_without_an_application_bound():
    # Applications load the redaction module on its own in a child process
    # (KEEN's bounded masking checks); finding tokens in text must not pull in
    # the token checks, which need the application's settings.
    code = (
        "import importlib.util, sys\n"
        "spec = importlib.util.spec_from_file_location('redaction', sys.argv[1])\n"
        "spec.loader.exec_module(importlib.util.module_from_spec(spec))\n"
    )
    subprocess.run([sys.executable, "-c", code, redaction.__file__], check=True)


def test_the_policy_merges_token_reads():
    merged = MOSP_POLICY | RoutePolicy(token_reads=RouteSet({"GET": ("/v1/a",)}))
    assert merged.token_reads.matches("GET", "/v1/a")
    assert not MOSP_POLICY.token_reads.matches("GET", "/v1/a")


# Issuing, listing and revoking.


@pytest.fixture
def mail(monkeypatch):
    monkeypatch.setattr(security_notifications, "smtp_configured", lambda: True)


def test_only_administrators_manage_tokens(site):
    user = site.user()
    client = site.client(user)
    assert client.get("/v1/admin/api-tokens").status_code == 403
    response = client.post(
        "/v1/admin/api-tokens",
        json={"name": "x", "user_id": str(user.id)},
        headers=unsafe(client),
    )
    assert response.status_code == 403


def test_issuing_tells_the_account_holder_and_lists_the_token(site, mail):
    admin = site.user(role="admin")
    user = site.user()
    site.db.get(User, user.id).email = "reader@example.org"
    site.db.commit()
    issued = _issue(site, user, admin=admin, expires_in_days=30)
    item = issued["item"]
    assert item["username"] == user.username
    assert item["created_by"] == admin.username
    assert item["status"] == "active"
    assert item["hint"] == issued["token"][-4:]
    assert item["expires_at"].endswith("Z")
    (notice,) = (
        site.db.query(SecurityNotification).filter_by(recipient="reader@example.org")
    ).all()
    assert notice.subject == (
        "TestApp security: An API token was issued for your TestApp account"
    )
    assert "keen reader" in notice.body
    assert f"By administrator: {admin.username}" in notice.body
    assert issued["token"] not in notice.body

    listing = site.client(admin).get("/v1/admin/api-tokens").json()["items"]
    assert [row["id"] for row in listing] == [item["id"]]
    assert "token" not in listing[0]
    assert not any(issued["token"] in str(value) for value in listing[0].values())


def test_a_token_without_an_expiry_never_expires(site, mail):
    user = site.user()
    site.db.get(User, user.id).email = "forever@example.org"
    site.db.commit()
    issued = _issue(site, user)
    assert issued["item"]["expires_at"] is None
    notice = (
        site.db.query(SecurityNotification)
        .filter_by(recipient="forever@example.org")
        .one()
    )
    assert "Expires: never" in notice.body


def test_an_empty_listing(site):
    client = site.client(site.user(role="admin"))
    assert client.get("/v1/admin/api-tokens").json() == {"enabled": True, "items": []}


def test_the_listing_shows_expired_and_revoked_tokens(site):
    user = site.user()
    admin = site.user(role="admin")
    first = _issue(site, user, admin=admin)["item"]["id"]
    second = _issue(site, user, admin=admin)["item"]["id"]
    expired = site.db.get(ApiToken, uuid.UUID(first))
    expired.expires_at = utc_now_naive() - timedelta(days=1)
    revoked = site.db.get(ApiToken, uuid.UUID(second))
    revoked.revoked_at = utc_now_naive()
    site.db.commit()
    listing = site.client(admin).get("/v1/admin/api-tokens").json()["items"]
    assert {row["id"]: row["status"] for row in listing} == {
        first: "expired",
        second: "revoked",
    }


@pytest.mark.parametrize(
    "fields, status",
    [
        ({"user_id": "not-a-uuid"}, 404),
        ({"user_id": str(uuid.uuid4())}, 404),
        ({"name": "   "}, 400),
        ({"expires_in_days": 0}, 422),
        ({"expires_in_days": 367}, 422),
    ],
)
def test_issuing_refuses_bad_requests(site, fields, status):
    user = site.user()
    client = site.client(site.user(role="admin"))
    response = client.post(
        "/v1/admin/api-tokens",
        json={"name": "reader", "user_id": str(user.id), **fields},
        headers=unsafe(client),
    )
    assert response.status_code == status, response.text


def test_inactive_accounts_are_issued_nothing(site):
    user = site.user()
    site.db.get(User, user.id).is_active = False
    site.db.commit()
    client = site.client(site.user(role="admin"))
    response = client.post(
        "/v1/admin/api-tokens",
        json={"name": "reader", "user_id": str(user.id)},
        headers=unsafe(client),
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "Active account not found"}


def test_an_account_holds_a_bounded_number_of_current_tokens(site, monkeypatch):
    from mosp.services import api_tokens as service

    monkeypatch.setattr(service, "MAX_CURRENT_PER_ACCOUNT", 2)
    user = site.user()
    admin = site.user(role="admin")
    first = _issue(site, user, admin=admin)["item"]["id"]
    _issue(site, user, admin=admin)
    client = site.client(admin)
    refused = client.post(
        "/v1/admin/api-tokens",
        json={"name": "third", "user_id": str(user.id)},
        headers=unsafe(client),
    )
    assert refused.status_code == 409
    # An expired token no longer counts.
    site.db.get(ApiToken, uuid.UUID(first)).expires_at = utc_now_naive()
    site.db.commit()
    _issue(site, user, admin=admin)


def test_revoking_ends_the_token_and_tells_the_account_holder(site, mail):
    admin = site.user(role="admin")
    user = site.user()
    site.db.get(User, user.id).email = "revoked@example.org"
    site.db.commit()
    issued = _issue(site, user, admin=admin)
    token, token_id = issued["token"], issued["item"]["id"]
    client = site.client(admin)
    path = f"/v1/admin/api-tokens/{token_id}/revoke"
    response = client.post(path, headers=unsafe(client))
    assert response.status_code == 200
    assert response.json()["item"]["status"] == "revoked"
    revoked_at = response.json()["item"]["revoked_at"]
    assert site.client().get("/v1/things", headers=_bearer(token)).status_code == 401
    subjects = [
        row.subject
        for row in site.db.query(SecurityNotification).filter_by(
            recipient="revoked@example.org"
        )
    ]
    assert "TestApp security: An API token for your TestApp account was revoked" in (
        subjects
    )
    # Revoking again changes nothing and sends nothing.
    again = client.post(path, headers=unsafe(client))
    assert again.json()["item"]["revoked_at"] == revoked_at
    assert (
        site.db.query(SecurityNotification)
        .filter_by(recipient="revoked@example.org")
        .count()
        == len(subjects)
        == 2
    )


@pytest.mark.parametrize("token_id", ["nope", str(uuid.uuid4())])
def test_revoking_an_unknown_token(site, token_id):
    client = site.client(site.user(role="admin"))
    response = client.post(
        f"/v1/admin/api-tokens/{token_id}/revoke", headers=unsafe(client)
    )
    assert response.status_code == 404


def test_api_tokens_are_off_by_default():
    from mosp.config import MospSettings

    assert MospSettings.model_fields["api_tokens_enabled"].default is False


def test_while_turned_off_no_token_is_accepted_or_issued(site, tokens_on):
    admin = site.user(role="admin")
    user, token = _token_for(site, admin=admin)
    token_id = site.db.query(ApiToken).one().id
    tokens_on.api_tokens_enabled = False
    assert api_tokens.enabled() is False
    reader = site.client()
    # The bearer credential is not read at all: the request has no account.
    assert reader.get("/v1/things", headers=_bearer(token)).status_code == 401
    client = site.client(admin)
    refused = client.post(
        "/v1/admin/api-tokens",
        json={"name": "x", "user_id": str(user.id)},
        headers=unsafe(client),
    )
    assert refused.status_code == 409
    assert refused.json()["detail"] == (
        "API tokens are turned off for this installation (TESTAPP_API_TOKENS_ENABLED)"
    )
    # Tokens issued earlier can still be reviewed and revoked.
    listing = client.get("/v1/admin/api-tokens").json()
    assert listing["enabled"] is False
    assert [row["id"] for row in listing["items"]] == [str(token_id)]
    revoked = client.post(
        f"/v1/admin/api-tokens/{token_id}/revoke", headers=unsafe(client)
    )
    assert revoked.json()["item"]["status"] == "revoked"
    # Turned on again, a revoked token stays refused.
    tokens_on.api_tokens_enabled = True
    assert reader.get("/v1/things", headers=_bearer(token)).status_code == 401
