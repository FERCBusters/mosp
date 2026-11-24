"""The sign-in identities SSO providers linked to an account: listed to its
holder, removable by them and by an operator, and never a directory's."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from mosp.security import mfa
from tests.assembled import unsafe
from tests.testapp.config import settings
from tests.testapp.models import (
    SecurityNotification,
    SsoEmailChallenge,
    User,
    UserIdentity,
    UserSsoEmail,
)


@pytest.fixture
def holder(site, monkeypatch):
    monkeypatch.setattr(settings, "smtp_host", "smtp.example")
    monkeypatch.setattr(settings, "smtp_from_email", "app@example.org")
    user = site.user()
    user.email = "owner@example.org"
    site.db.commit()

    def link(subject, *, provider="oidc", email=None, owner=user):
        identity = UserIdentity(
            user_id=owner.id,
            provider=provider,
            issuer="https://idp.example",
            subject=subject,
            email=email,
            display_name=f"Person {subject}",
        )
        site.db.add(identity)
        site.db.commit()
        return identity

    return site, user, site.client(user), link


def _remove(client, identity_id):
    response = client.post(
        "/v1/me/sso-identities/remove",
        json={"id": identity_id},
        headers=unsafe(client),
    )
    return response.status_code, response.json()


def _notices(site):
    site.db.expire_all()
    return [
        n.subject.removeprefix("TestApp security: ")
        for n in site.db.query(SecurityNotification).filter_by(
            recipient="owner@example.org"
        )
    ]


def test_the_holder_sees_the_identities_providers_linked(holder):
    site, user, client, link = holder
    first = link("first", email="work@example.org")
    link("second", provider="github")
    link("directory", provider="ldap")
    link("theirs", owner=site.user())

    listed = client.get("/v1/me/sso-identities").json()["identities"]
    assert [(i["id"], i["provider"], i["email"], i["name"]) for i in listed] == [
        (first.id, "oidc", "work@example.org", "Person first"),
        (listed[1]["id"], "github", None, "Person second"),
    ]
    assert listed[0]["linked_at"] == first.created_at.isoformat()
    assert listed[0]["last_used_at"] == first.updated_at.isoformat()


def test_removing_an_identity_unlinks_it_ends_every_session_and_tells_the_holder(
    holder,
):
    site, user, client, link = holder
    identity = link("planted", email="planted@attacker.example")
    kept = link("own", email="work@example.org")
    for email in ("planted@attacker.example", "work@example.org"):
        site.db.add(UserSsoEmail(email=email, user_id=user.id))
    site.db.add(
        SsoEmailChallenge(
            token_hash="h" * 64,
            user_id=user.id,
            email="planted@attacker.example",
            expires_at=datetime(2099, 1, 1),
            mfa_version=user.mfa_version,
            password_digest="d",
        )
    )
    site.db.commit()
    before = user.session_version

    assert _remove(client, identity.id) == (
        200,
        {
            "ok": True,
            "addresses": ["work@example.org"],
            "identities": ["oidc: work@example.org"],
        },
    )

    site.db.expire_all()
    assert [i.id for i in site.db.query(UserIdentity).filter_by(user_id=user.id)] == [
        kept.id
    ]
    # The address it linked through goes too, or it would link again.
    assert [a.email for a in site.db.query(UserSsoEmail)] == ["work@example.org"]
    assert site.db.query(SsoEmailChallenge).count() == 0
    assert site.db.get(User, user.id).session_version == before + 1
    assert client.get("/v1/auth/check").status_code == 401
    (notice,) = site.db.query(SecurityNotification).all()
    assert notice.subject.endswith(
        "A sign-in identity was removed from your TestApp account"
    )
    # The notice names what is left, for the holder to review.
    assert "Identity removed: planted@attacker.example" in notice.body
    assert "Linking addresses still on the account: work@example.org" in notice.body
    assert "Sign-in identities still linked: oidc: work@example.org" in notice.body


def test_an_identity_without_an_email_is_named_by_its_profile(holder):
    site, user, client, link = holder
    identity = link("bare")
    identity.preferred_username = "octocat"
    site.db.commit()
    assert _remove(client, identity.id)[0] == 200
    site.db.expire_all()
    (notice,) = site.db.query(SecurityNotification).all()
    assert "Identity removed: octocat" in notice.body

    other = holder[0].client(user)
    unnamed = link("only-a-subject")
    assert _remove(other, unnamed.id)[0] == 200
    site.db.expire_all()
    assert any(
        "Identity removed: only-a-subject" in n.body
        for n in site.db.query(SecurityNotification)
    )


def test_directory_identities_and_other_accounts_identities_are_left_alone(holder):
    site, user, client, link = holder
    directory = link("directory", provider="ldap")
    theirs = link("theirs", owner=site.user())
    for identity_id in (directory.id, theirs.id, 999_999_999):
        assert _remove(client, identity_id) == (200, {"ok": True})
    site.db.expire_all()
    assert site.db.query(UserIdentity).count() == 2
    assert _notices(site) == []
    # Nothing was removed, so the session goes on.
    assert client.get("/v1/auth/check").status_code == 204


def test_removing_an_identity_needs_a_recent_sign_in(holder):
    site, user, client, link = holder
    identity = link("planted")
    (key,) = site.store.keys("testapp:session:*")
    stored = json.loads(site.store.get(key))
    stored["created_at"] = (
        datetime.now(timezone.utc) - timedelta(minutes=6)
    ).isoformat()
    site.store.set(key, json.dumps(stored))

    assert _remove(client, identity.id)[0] == 403
    assert site.db.query(UserIdentity).count() == 1


@pytest.mark.parametrize("body", [{}, {"id": 0}, {"id": "x"}])
def test_a_malformed_removal_is_refused(holder, body):
    site, user, client, link = holder
    response = client.post(
        "/v1/me/sso-identities/remove", json=body, headers=unsafe(client)
    )
    assert response.status_code == 422


def test_an_operator_reset_unlinks_provider_identities(holder):
    site, user, client, link = holder
    link("planted")
    link("directory", provider="ldap")
    before = user.session_version

    mfa.operator_reset(site.db, user)
    site.db.commit()

    site.db.expire_all()
    assert [i.provider for i in site.db.query(UserIdentity)] == ["ldap"]
    assert site.db.get(User, user.id).session_version == before + 1
    assert client.get("/v1/auth/check").status_code == 401


def test_removal_reaches_the_linking_address_whatever_the_provider_reports_later(
    holder,
):
    from mosp.security import oidc

    site, user, client, link = holder
    identity = link("drifting", email="planted@attacker.example")
    site.db.add(UserSsoEmail(email="planted@attacker.example", user_id=user.id))
    site.db.commit()
    # A later sign-in reports another address; the link keeps its own.
    oidc._update_identity_metadata(
        identity, {"email": "drift@attacker.example", "email_verified": True}
    )
    site.db.commit()
    assert client.get("/v1/me/sso-identities").json()["identities"][0]["email"] == (
        "planted@attacker.example"
    )

    assert _remove(client, identity.id)[0] == 200
    site.db.expire_all()
    assert site.db.query(UserSsoEmail).count() == 0


def test_an_operator_reset_removes_the_linking_addresses_too(holder):
    site, user, client, link = holder
    link("planted", email="planted@attacker.example")
    site.db.add(UserSsoEmail(email="planted@attacker.example", user_id=user.id))
    site.db.add(
        SsoEmailChallenge(
            token_hash="c" * 64,
            user_id=user.id,
            email="pending@attacker.example",
            expires_at=datetime(2099, 1, 1),
            mfa_version=user.mfa_version,
            password_digest="d",
        )
    )
    other = site.user()
    site.db.add(UserSsoEmail(email="theirs@example.org", user_id=other.id))
    site.db.commit()

    mfa.operator_reset(site.db, user)
    site.db.commit()

    site.db.expire_all()
    assert [a.email for a in site.db.query(UserSsoEmail)] == ["theirs@example.org"]
    assert site.db.query(SsoEmailChallenge).count() == 0


def test_the_accounts_only_way_to_sign_in_is_not_removed(holder, monkeypatch):
    site, user, client, link = holder
    only = link("only", email="work@example.org")
    monkeypatch.setattr(settings, "local_auth_enabled", False)
    assert _remove(client, only.id) == (
        409,
        {
            "detail": "This identity is the account's only way to sign in; link "
            "another before removing it"
        },
    )
    site.db.expire_all()
    assert site.db.query(UserIdentity).count() == 1
    # With a second identity linked, either can go.
    link("second")
    assert _remove(client, only.id)[0] == 200


@pytest.mark.parametrize(
    "setting,backend,expected",
    [
        ({"trust_remote_user": True, "local_auth_enabled": False}, "local", True),
        ({"ldap_enabled": True, "local_auth_enabled": False}, "ldap", True),
        ({"ldap_enabled": False}, "ldap", False),
        ({"local_auth_enabled": True}, "local", True),
        ({"local_auth_enabled": False}, "local", False),
    ],
)
def test_ways_to_sign_in_other_than_sso(site, monkeypatch, setting, backend, expected):
    for name, value in setting.items():
        monkeypatch.setattr(settings, name, value)
    user = site.user()
    user.auth_backend = backend
    assert mfa.signs_in_without_sso(user) is expected


def test_an_operator_reset_leaves_an_sso_only_accounts_way_in(holder, monkeypatch):
    site, user, client, link = holder
    link("owner", email="work@example.org")
    site.db.add(UserSsoEmail(email="work@example.org", user_id=user.id))
    site.db.commit()
    monkeypatch.setattr(settings, "local_auth_enabled", False)
    before = user.session_version

    mfa.operator_reset(site.db, user)
    site.db.commit()

    site.db.expire_all()
    assert site.db.query(UserIdentity).count() == 1
    assert site.db.query(UserSsoEmail).count() == 1
    assert site.db.get(User, user.id).session_version == before + 1


def test_an_operator_reset_can_keep_one_identity_of_an_sso_only_account(
    holder, monkeypatch
):
    # Someone who took the account over linked their own identity and removed
    # the owner's; the operator keeps the identity the owner names.
    site, user, client, link = holder
    owner = link("owner", email="work@example.org")
    link("planted", email="planted@attacker.example")
    link("directory", provider="ldap")
    site.db.add(UserSsoEmail(email="planted@attacker.example", user_id=user.id))
    site.db.commit()
    monkeypatch.setattr(settings, "local_auth_enabled", False)

    with pytest.raises(ValueError, match="no such SSO identity"):
        mfa.operator_reset(site.db, user, keep_identity=owner.id + 1000)
    site.db.rollback()
    mfa.operator_reset(site.db, user, keep_identity=owner.id)
    site.db.commit()

    site.db.expire_all()
    assert sorted(i.subject for i in site.db.query(UserIdentity)) == [
        "directory",
        "owner",
    ]
    assert site.db.query(UserSsoEmail).count() == 0


def test_an_operator_reset_can_give_an_sso_only_account_a_new_linking_address(
    holder, monkeypatch
):
    # Someone who took the account over removed the owner's identity, so none
    # is left to keep: every SSO identity goes, and the address the owner
    # confirmed out of band is the only one left to link through.
    site, user, client, link = holder
    link("planted", email="planted@attacker.example")
    link("directory", provider="ldap")
    site.db.add(UserSsoEmail(email="planted@attacker.example", user_id=user.id))
    site.db.commit()
    monkeypatch.setattr(settings, "local_auth_enabled", False)

    with pytest.raises(ValueError, match="not both"):
        mfa.operator_reset(site.db, user, keep_identity=1, link_address="a@b.example")
    with pytest.raises(ValueError, match="Invalid email address"):
        mfa.operator_reset(site.db, user, link_address="not an address")
    other = site.user()
    other.email = "taken@example.org"
    site.db.commit()
    with pytest.raises(ValueError, match="cannot be linked"):
        mfa.operator_reset(site.db, user, link_address="Taken@Example.org")
    mfa.operator_reset(site.db, user, link_address=" Work@Example.org ")
    site.db.commit()

    site.db.expire_all()
    assert [i.subject for i in site.db.query(UserIdentity)] == ["directory"]
    assert [(a.email, a.user_id) for a in site.db.query(UserSsoEmail)] == [
        ("work@example.org", user.id)
    ]
