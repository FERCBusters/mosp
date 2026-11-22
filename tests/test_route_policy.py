"""Which writes a signed-in account may make, as the middleware decides from
myf's route policy merged with the application's, and the first
administrator an empty installation is given."""

import pytest
from sqlalchemy.orm import sessionmaker

from myf import middleware
from myf.security import route_policy
from myf.security.route_policy import (
    MYF_POLICY,
    PrefixRule,
    RouteCodes,
    RoutePolicy,
    RouteSet,
)
from tests.assembled import PASSWORD, unsafe
from tests.testapp import hooks as testapp_hooks
from tests.testapp.config import settings
from tests.testapp.models import User


def _write(site, path, *codes, role="normal"):
    client = site.client(site.user(*codes, role=role))
    response = client.post(path, headers=unsafe(client))
    return response.status_code, response.json()


def test_an_ordinary_write_needs_an_administrator(site):
    assert _write(site, "/v1/things") == (
        403,
        {"detail": "Read-only users cannot perform write actions"},
    )
    assert _write(site, "/v1/things", role="admin") == (200, {"made": True})


def test_a_route_that_checks_its_own_object_is_left_to_do_so(site):
    assert _write(site, "/v1/notes/7") == (200, {"note": 7})


def test_a_gated_write_needs_its_permission(site):
    assert _write(site, "/v1/gated") == (
        403,
        {"detail": "gated.write permission required"},
    )
    assert _write(site, "/v1/gated", "gated.write") == (200, {"gated": True})
    # An administrator holds every permission.
    assert _write(site, "/v1/gated", role="admin") == (200, {"gated": True})


def test_writes_under_a_prefix_need_one_of_its_permissions(site):
    assert _write(site, "/v1/reports/run") == (
        403,
        {"detail": "reports.run permission required"},
    )
    assert _write(site, "/v1/reports/run", "reports.run") == (200, {"ran": True})


def test_an_administrator_namespace_refuses_reads_too(site):
    reader = site.client(site.user())
    assert (reader.get("/v1/admin/overview").json()) == {
        "detail": "Admin role required"
    }
    admin = site.client(site.user(role="admin"))
    assert admin.get("/v1/admin/overview").json() == {"admin": True}


def test_a_self_service_prefix_covers_every_route_below_it(site, hook):
    own = RoutePolicy(self_service_prefixes=("/v1/things",))
    hook(route_policy=lambda: testapp_hooks.POLICY | own)
    assert _write(site, "/v1/things") == (200, {"made": True})


def test_policies_merge_and_are_recomputed_when_the_application_changes_its_own(
    hook,
):
    first = RoutePolicy(
        public=RouteSet({"get": ("/a/{id}",)}),
        gated=RouteCodes({("post", "/a"): "a.write"}),
        prefix_rules=(PrefixRule("/a", ("a.one", "a.two")),),
    )
    second = RoutePolicy(
        public=RouteSet({"GET": ("/b",), "POST": ("/b",)}),
        gated=RouteCodes({("POST", "/b"): "b.write"}),
        prefix_rules=(PrefixRule("/b", ("b.run",), "Ask for b"),),
        unaudited_paths=frozenset({"/b"}),
    )
    merged = first | second
    assert merged.public.matches("get", "/a/1") and merged.public.matches("POST", "/b")
    assert not merged.public.matches("POST", "/a/1")
    assert merged.public.routes == {"GET": ("/a/{id}", "/b"), "POST": ("/b",)}
    assert merged.gated.lookup("POST", "/a") == "a.write"
    assert merged.gated.lookup("post", "/b") == "b.write"
    assert merged.gated.lookup("GET", "/b", "none") == "none"
    assert [rule.refusal() for rule in merged.prefix_rules] == [
        "a.one or a.two permission required",
        "Ask for b",
    ]
    assert merged.unaudited_paths == {"/b"}

    hook(route_policy=lambda: first)
    assert route_policy.policy().gated.lookup("POST", "/a") == "a.write"
    hook(route_policy=lambda: None)
    assert route_policy.policy() is MYF_POLICY
    hook(route_policy=lambda: second)
    assert route_policy.policy().gated.lookup("POST", "/a") is None
    assert route_policy.policy().gated.lookup("POST", "/b") == "b.write"


# -- the first administrator --------------------------------------------------


@pytest.fixture
def empty_installation(db, monkeypatch):
    factory = sessionmaker(
        bind=db.get_bind(),
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )
    monkeypatch.setattr(middleware, "SessionLocal", factory)

    def configure(username, password):
        monkeypatch.setattr(settings, "bootstrap_admin_username", username)
        monkeypatch.setattr(settings, "bootstrap_admin_password", password)

    return db, configure


def test_an_empty_installation_gets_its_first_administrator(empty_installation, capsys):
    db, configure = empty_installation
    configure(" first-admin ", f" {PASSWORD} ")

    middleware.bootstrap_initial_admin()

    (user,) = db.query(User).all()
    assert (user.username, user.role) == ("first-admin", "admin")
    assert "[testapp] Bootstrapped initial admin user: first-admin" in (
        capsys.readouterr().out
    )
    # Later starts find the account and leave it be.
    configure("someone-else", PASSWORD)
    middleware.bootstrap_initial_admin()
    assert db.query(User).count() == 1


def test_no_account_is_made_without_both_credentials_or_where_refused(
    empty_installation, hook
):
    db, configure = empty_installation
    configure("", "")
    middleware.bootstrap_initial_admin()
    configure("admin", PASSWORD)
    hook(bootstrap_allowed=lambda: False)
    middleware.bootstrap_initial_admin()
    assert db.query(User).count() == 0


@pytest.mark.parametrize(
    "username,password",
    [("admin", ""), ("", PASSWORD), ("admin", "<GENERATE_PASSWORD>"), ("a", "short")],
)
def test_bootstrap_failures_name_the_settings_and_nothing_supplied(
    empty_installation, username, password
):
    db, configure = empty_installation
    configure(username, password)

    with pytest.raises(RuntimeError) as failed:
        middleware.bootstrap_initial_admin()

    message = str(failed.value)
    assert "TESTAPP_BOOTSTRAP_ADMIN_USERNAME" in message
    assert "TESTAPP_BOOTSTRAP_ADMIN_PASSWORD" in message
    assert f"at least {settings.password_min_length} characters" in message
    assert failed.value.__cause__ is None and failed.value.__suppress_context__
    if password:
        assert password not in message
    assert db.query(User).count() == 0
