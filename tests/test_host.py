import pytest

from myf import host
from myf.host import hooks


def test_the_bound_application_names_its_keys_messages_and_settings():
    assert (host.name(), host.title()) == ("testapp", "TestApp")
    assert host.env("smtp_host") == "TESTAPP_SMTP_HOST"


def test_a_role_cannot_be_rebound_to_another_module():
    with pytest.raises(RuntimeError, match="already bound"):
        host.bind(name="testapp", title="TestApp", config="other.config")
    with pytest.raises(RuntimeError, match="already"):
        host.bind(name="other", title="TestApp")
    with pytest.raises(ValueError, match="Unknown myf host roles"):
        host.bind(name="testapp", title="TestApp", storage="x")


def test_an_unbound_role_says_how_to_bind_it():
    with pytest.raises(RuntimeError, match=r"No application is bound to myf's 'db'"):
        host.module("db")


def test_hooks_an_application_leaves_out_keep_their_defaults():
    assert hooks.session_allowed(None, None, {}) is True
    assert hooks.sign_in_methods() == {}
    assert hooks.permission_implications() == {}
    assert hooks.origin_required() is False
    assert hooks.body_limit("/anything") == hooks.DEFAULT_BODY_LIMIT
    assert hooks.encoded_slash_routes() is None
    assert hooks.measured_fields() == {}
    assert hooks.issued_secret_pattern() is None
    assert hooks.security_notice("login-ip") is None
    hooks.user_created(None, None)
    hooks.sso_identity_allowed("oidc", "https://idp.example", "subject")
    from fastapi.routing import APIRoute

    assert hooks.route_class() is APIRoute


def test_an_application_hook_replaces_the_default(hook):
    calls = []
    hook(
        session_allowed=lambda db, user, session: False,
        user_created=lambda db, user: calls.append(user),
        sign_in_methods=lambda: {"demo": None},
        origin_required=lambda: True,
        body_limit=lambda path: 10,
    )
    assert hooks.session_allowed(None, None, {}) is False
    hooks.user_created(None, "new")
    assert calls == ["new"]
    assert hooks.sign_in_methods() == {"demo": None}
    assert hooks.origin_required() is True
    assert hooks.body_limit("/x") == 10


def test_an_application_name_is_a_lower_case_identifier():
    from myf.host import _identity

    saved = dict(_identity)
    _identity.clear()
    try:
        with pytest.raises(ValueError, match="lower-case identifier"):
            host.bind(name="Test-App", title="x")
    finally:
        _identity.clear()
        _identity.update(saved)
