"""Roles, permission codes, group names, action records and request context."""

import uuid

import pytest
from starlette.requests import Request

from myf.api.context import change_context, machine_credential, mark_machine_credential
from myf.security import permissions, roles
from myf.services.activity_log import record_action
from myf.services.context import ChangeContext, signed_in_user
from myf.services.errors import DomainError
from tests.testapp.models import AuditLog, Group, Permission, User


def _user(db, role="normal", **fields):
    user = User(
        username=f"u-{role}-{uuid.uuid4().hex}",
        password_hash="unused",
        role=role,
        is_active=True,
        **fields,
    )
    db.add(user)
    db.flush()
    return user


# -- roles --------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,role",
    [
        (" Admin ", "admin"),
        ("normal", "normal"),
        ("INHERIT", "inherit"),
        ("", None),
        (None, None),
        ("owner", None),
    ],
)
def test_roles_have_three_spellings(raw, role):
    assert roles.normalize_role(raw) == role


def test_an_inheriting_account_takes_the_strongest_group_role(db):
    inheriting = _user(db, role="inherit")
    assert roles.compute_effective_role(db, inheriting) == "normal"
    readers = Group(name="readers", role="normal")
    blank = Group(name="blank", role=None)
    db.add_all([readers, blank])
    db.flush()
    inheriting.groups.extend([readers, blank])
    db.flush()
    assert roles.compute_effective_role(db, inheriting) == "normal"
    admins = Group(name="admins", role="admin")
    db.add(admins)
    db.flush()
    inheriting.groups.append(admins)
    db.flush()
    assert roles.compute_effective_role(db, inheriting) == "admin"
    assert roles.is_effective_admin(db, inheriting)


def test_an_unknown_or_inactive_role_is_normal(db):
    odd = _user(db, role="owner")
    assert roles.compute_effective_role(db, odd) == "normal"
    gone = _user(db, role="admin")
    gone.is_active = False
    assert roles.compute_effective_role(db, gone) == "normal"
    assert roles.compute_effective_role(db, None) == "normal"


def test_an_attached_role_is_used_as_it_is(db):
    admin = _user(db, role="admin")
    admin.effective_role = "normal"
    assert not roles.is_effective_admin(db, admin)
    admin.effective_role = None
    assert roles.is_effective_admin(db, admin)
    assert roles.attach_effective_role(db, admin) == "admin"
    assert admin.effective_role == "admin"


# -- permission codes and group names -----------------------------------------


def test_permission_codes_are_trimmed_deduplicated_bounded_and_sorted():
    assert permissions.normalize_permission_codes(None) == []
    assert permissions.normalize_permission_codes(
        ["b.read", " a.read ", "", "  ", None, "b.read", "x" * 129, "x" * 128]
    ) == ["a.read", "b.read", "x" * 128]


def test_group_names_and_descriptions_are_trimmed():
    assert permissions.normalize_group_name("  Ops ") == "Ops"
    assert permissions.normalize_group_name(None) == ""
    assert permissions.normalize_group_description("  ") is None
    assert permissions.normalize_group_description(None) is None
    assert permissions.normalize_group_description(" On call ") == "On call"


def test_any_of_several_permissions_will_do(db):
    reader = _user(db)
    code = Permission(code="things.read", description="things.read")
    db.add(code)
    db.flush()
    reader.permissions.append(code)
    db.flush()
    assert permissions.has_any_permission(db, reader, "things.write", "things.read")
    assert not permissions.has_any_permission(db, reader, "things.write")
    assert not permissions.has_any_permission(db, reader)


# -- action records -----------------------------------------------------------


def test_an_action_is_recorded_with_bounded_redacted_context(db):
    actor = _user(db)
    context = ChangeContext(
        client_ip="203.0.113.5",
        user_agent=" " + "u" * 300,
        referer="https://idp.example/cb?token=secret-code&x=" + "r" * 600,
    )
    record_action(db, context, actor, "thing.made", {"id": 7, "skip": None})
    record_action(db, ChangeContext(user_agent="  "), None, "thing.seen")
    db.flush()

    rows = {row.path: row for row in db.query(AuditLog).all()}
    made, seen = rows["/action/thing.made"], rows["/action/thing.seen"]
    assert (made.method, made.path, made.status_code) == (
        "ACTION",
        "/action/thing.made",
        200,
    )
    assert (made.username, made.query_string, made.client_ip) == (
        actor.username,
        "id=7",
        "203.0.113.5",
    )
    assert made.user_agent == "u" * 256
    assert len(made.referer) == 512 and "secret-code" not in made.referer
    assert (seen.username, seen.query_string, seen.user_agent, seen.referer) == (
        None,
        None,
        None,
        None,
    )


def test_details_that_cannot_be_written_are_left_out(db):
    class Unprintable:
        def __str__(self):
            raise RuntimeError("no text")

    record_action(db, ChangeContext(), None, "odd", {"value": Unprintable()})
    db.flush()
    (row,) = db.query(AuditLog).filter_by(path="/action/odd").all()
    assert row.query_string is None


# -- request context ----------------------------------------------------------


def test_a_change_needs_a_signed_in_account(db):
    actor = _user(db)
    assert signed_in_user(ChangeContext(actor=actor)) is actor
    with pytest.raises(DomainError) as refused:
        signed_in_user(ChangeContext(actor="someone"))
    assert (refused.value.status_code, refused.value.detail) == (
        401,
        "Not authenticated",
    )


def test_a_request_names_its_context_and_machine_credential():
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/v1/hook",
            "headers": [(b"user-agent", b"agent/1"), (b"referer", b"https://r")],
            "client": ("203.0.113.9", 1234),
            "server": ("app.example", 443),
            "scheme": "https",
            "query_string": b"",
            "state": {},
        }
    )
    assert machine_credential(request) is None
    mark_machine_credential(request, "webhook-secret")
    assert machine_credential(request) == "webhook-secret"
    context = change_context(request)
    assert (context.method, context.path, context.actor) == ("POST", "/v1/hook", None)
    assert (context.user_agent, context.referer) == ("agent/1", "https://r")


def test_authorisation_changes_reach_every_affected_session(db):
    first, second, untouched = _user(db), _user(db), _user(db)
    group = Group(name="moved", role=None)
    db.add(group)
    db.flush()
    group.users.extend([first, second])
    db.flush()

    assert sorted(permissions.group_member_ids(db, group.id)) == sorted(
        [first.id, second.id]
    )
    permissions.bump_authz_versions(
        db, permissions.group_member_ids(db, group.id) + [None]
    )
    permissions.bump_authz_versions(db, [])
    db.expire_all()
    assert (first.authz_version, second.authz_version, untouched.authz_version) == (
        1,
        1,
        0,
    )
