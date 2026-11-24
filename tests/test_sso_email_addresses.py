"""Self-service SSO linking addresses: proof of ownership by email, recent
sign-in, limits, and addresses other accounts already use."""

import json
import re
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from mosp.core.datetime_utils import utc_now_naive
from mosp.services import sso_emails
from mosp.services.errors import DomainError
from tests.assembled import unsafe
from tests.testapp.config import settings
from tests.testapp.models import (
    SecurityNotification,
    SsoEmailChallenge,
    User,
    UserSsoEmail,
)

TOKEN = re.compile(r"#token=([A-Za-z0-9_-]+)")


@pytest.fixture
def account(site, monkeypatch):
    monkeypatch.setattr(settings, "smtp_host", "smtp.example")
    monkeypatch.setattr(settings, "smtp_from_email", "app@example.org")
    user = site.user()
    user.email = "owner@example.org"
    site.db.commit()
    client = site.client(user)

    def post(action, **body):
        response = client.post(
            f"/v1/me/sso-emails/{action}", json=body, headers=unsafe(client)
        )
        return response.status_code, response.json()

    def link_for(email):
        site.db.expire_all()
        (mail,) = (
            site.db.query(SecurityNotification)
            .filter_by(recipient=email)
            .order_by(SecurityNotification.created_at.desc())
            .limit(1)
            .all()
        )
        return TOKEN.search(mail.body).group(1)

    return site, user, client, post, link_for


def test_an_address_is_linked_once_its_owner_follows_the_link(account):
    site, user, client, post, link_for = account

    assert post("request", email=" Work@Example.org ") == (200, {"ok": True})
    token = link_for("work@example.org")
    assert post("confirm", token=token) == (
        200,
        {"ok": True, "email": "work@example.org"},
    )
    listed = client.get("/v1/me/sso-emails").json()
    assert listed["smtp_configured"] is True
    assert listed["primary_email"] == "owner@example.org"
    assert [a["email"] for a in listed["addresses"]] == ["work@example.org"]
    # The account holder is told, and the link works once.
    subjects = [
        n.subject
        for n in site.db.query(SecurityNotification).filter_by(
            recipient="owner@example.org"
        )
    ]
    assert subjects == [
        "TestApp security: An SSO email address was verified for your TestApp account"
    ]
    assert post("confirm", token=token) == (
        400,
        {"detail": "Verification link is invalid or expired"},
    )
    assert post("request", email="work@example.org") == (
        200,
        {"ok": True, "already_verified": True},
    )

    # A link for an address the account already holds confirms it again.
    post("request", email="again@example.org")
    token = link_for("again@example.org")
    site.db.add(
        UserSsoEmail(
            email="again@example.org", user_id=user.id, verified_at=utc_now_naive()
        )
    )
    site.db.commit()
    assert post("confirm", token=token) == (
        200,
        {"ok": True, "email": "again@example.org"},
    )
    post("remove", email="again@example.org")

    assert post("remove", email="WORK@example.org") == (200, {"ok": True})
    assert client.get("/v1/me/sso-emails").json()["addresses"] == []
    # Removing an address that is not linked tells nobody anything.
    before = site.db.query(SecurityNotification).count()
    assert post("remove", email="work@example.org") == (200, {"ok": True})
    assert site.db.query(SecurityNotification).count() == before


def test_a_link_stops_working_when_the_account_changes(account):
    site, user, client, post, link_for = account
    post("request", email="work@example.org")
    token = link_for("work@example.org")

    row = site.db.query(SsoEmailChallenge).one()
    row.mfa_version = (row.mfa_version or 0) + 1
    site.db.commit()
    assert post("confirm", token=token)[0] == 400

    post("request", email="work@example.org")
    token = link_for("work@example.org")
    row = site.db.query(SsoEmailChallenge).one()
    row.password_digest = "changed"
    site.db.commit()
    assert post("confirm", token=token)[0] == 400

    post("request", email="work@example.org")
    token = link_for("work@example.org")
    row = site.db.query(SsoEmailChallenge).one()
    row.expires_at = utc_now_naive() - timedelta(seconds=1)
    site.db.commit()
    assert post("confirm", token=token)[0] == 400


def test_an_address_another_account_uses_gets_the_same_answer_and_no_link(account):
    site, user, client, post, link_for = account
    other = site.user()
    other.email = "Taken@example.org"
    site.db.add(
        UserSsoEmail(
            email="linked@example.org", user_id=other.id, verified_at=utc_now_naive()
        )
    )
    site.db.commit()

    for email in ("taken@example.org", "linked@example.org"):
        assert post("request", email=email) == (200, {"ok": True})
        assert (
            site.db.query(SecurityNotification).filter_by(recipient=email).count() == 0
        )
    # A link sent before the address was taken is refused at confirmation.
    post("request", email="late@example.org")
    token = link_for("late@example.org")
    site.db.add(
        UserSsoEmail(
            email="late@example.org", user_id=other.id, verified_at=utc_now_naive()
        )
    )
    site.db.commit()
    assert post("confirm", token=token) == (
        409,
        {"detail": "This address cannot be linked to this account"},
    )


def test_a_concurrent_link_of_the_same_address_is_refused(account, monkeypatch):
    site, user, client, post, link_for = account
    post("request", email="race@example.org")
    token = link_for("race@example.org")
    original = Session.commit

    def racing(self):
        # Another request links the address between the check and the commit.
        if any(isinstance(row, UserSsoEmail) for row in self.new):
            self.rollback()
            raise IntegrityError("INSERT", {}, Exception("duplicate"))
        return original(self)

    monkeypatch.setattr(Session, "commit", racing)
    assert post("confirm", token=token) == (
        409,
        {"detail": "This address cannot be linked to this account"},
    )


def test_requests_need_mail_https_and_a_recent_sign_in(account, monkeypatch):
    site, user, client, post, link_for = account

    # Checked before anything else the request does; the route's own Origin
    # check would refuse a browser on a plain-HTTP site first.
    monkeypatch.setattr(settings, "public_base_url", "http://app.example")
    with pytest.raises(DomainError) as refused:
        sso_emails.request_address(
            payload=sso_emails.Address(email="a@example.org"),
            context=None,
            user=user,
            db=site.db,
            session_id="",
        )
    assert (refused.value.status_code, refused.value.detail) == (
        503,
        "An HTTPS TESTAPP_PUBLIC_BASE_URL is required for verification emails",
    )
    monkeypatch.setattr(settings, "public_base_url", "https://app.example")
    monkeypatch.setattr(settings, "smtp_host", "")
    assert post("request", email="a@example.org") == (
        503,
        {"detail": "SMTP must be configured before verifying SSO email addresses"},
    )
    monkeypatch.setattr(settings, "smtp_host", "smtp.example")

    # A session signed in more than five minutes ago must sign in again.
    (key,) = site.store.keys("testapp:session:*")
    stored = json.loads(site.store.get(key))
    stored["created_at"] = (
        datetime.now(timezone.utc) - timedelta(minutes=6)
    ).isoformat()
    site.store.set(key, json.dumps(stored))
    stale = (
        403,
        {
            "detail": "Sign out and sign in again, then manage SSO email addresses"
            " and sign-in identities within five minutes"
        },
    )
    assert post("request", email="a@example.org") == stale
    assert post("remove", email="a@example.org") == stale
    # A session that ended since the request was authenticated is not recent.
    with pytest.raises(DomainError) as ended:
        sso_emails.recent_signin("no-such-session", user)
    assert (ended.value.status_code, ended.value.detail) == (403, stale[1]["detail"])


def test_requests_are_limited_and_addresses_bounded(account):
    site, user, client, post, link_for = account
    for n in range(10):
        site.db.add(
            UserSsoEmail(
                email=f"a{n}@example.org", user_id=user.id, verified_at=utc_now_naive()
            )
        )
    site.db.commit()
    assert post("request", email="b@example.org") == (
        400,
        {"detail": "Remove an address before adding more than ten SSO email addresses"},
    )
    for _ in range(4):
        post("request", email="b@example.org")
    assert post("request", email="b@example.org") == (
        429,
        {"detail": "Too many verification requests; try again later"},
    )


def test_an_invalid_address_is_refused(account):
    site, user, client, post, link_for = account
    assert post("request", email="a@b@c") == (400, {"detail": "Invalid email address"})
    with pytest.raises(DomainError) as refused:
        sso_emails.clean_email("   ")
    assert refused.value.detail == "Invalid email address"


def test_an_inactive_account_cannot_link(account):
    site, user, client, post, link_for = account
    user.is_active = False
    site.db.commit()
    with pytest.raises(DomainError) as refused:
        sso_emails.lock_user(site.db, user)
    assert (refused.value.status_code, refused.value.detail) == (
        403,
        "Account is inactive",
    )
    assert site.db.get(User, user.id) is not None
