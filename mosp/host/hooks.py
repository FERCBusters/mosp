"""Points where mosp asks the application to take part.

An application defines any of these functions in the module it binds to the
``hooks`` role; a hook it leaves out keeps mosp's default. Hooks are looked up
on every call, so an application can import lazily inside its own hooks.
"""

from __future__ import annotations

from typing import Any

from mosp.host import _bound, module


def _hook(name: str):
    if "hooks" not in _bound:
        return None
    return getattr(module("hooks"), name, None)


def session_allowed(db: Any, user: Any, session: dict[str, Any]) -> bool:
    """Whether a stored session may still sign ``user`` in (default: yes)."""
    hook = _hook("session_allowed")
    return True if hook is None else bool(hook(db, user, session))


def user_created(db: Any, user: Any) -> None:
    """Called after a new account is flushed, before it is committed."""
    hook = _hook("user_created")
    if hook is not None:
        hook(db, user)


def sso_identity_allowed(provider_key: str, issuer: str, subject: str) -> None:
    """Raise to refuse a single sign-on identity before it reaches an account."""
    hook = _hook("sso_identity_allowed")
    if hook is not None:
        hook(provider_key, issuer, subject)


def sign_in_methods() -> dict[str, Any]:
    """Application-specific entries for ``GET /v1/auth/methods``."""
    hook = _hook("sign_in_methods")
    return {} if hook is None else dict(hook())


def route_dependencies() -> tuple[Any, ...]:
    """Dependencies every route of the application runs, such as its feature
    switches (default: none)."""
    hook = _hook("route_dependencies")
    return () if hook is None else tuple(hook())


def security_notice(event: str) -> tuple[str, str] | None:
    """The title and explanation of a security notice the application adds
    (an event mosp does not send itself); None for mosp's own events."""
    hook = _hook("security_notice")
    return None if hook is None else hook(event)


def origin_required() -> bool:
    """Whether browser writes must carry an Origin header (default: no, so
    clients that send none still reach routes that check their own proof)."""
    hook = _hook("origin_required")
    return False if hook is None else bool(hook())


def permission_implications() -> dict[str, frozenset[str]]:
    """Permissions that include others (default: none)."""
    hook = _hook("permission_implications")
    return {} if hook is None else hook()


DEFAULT_BODY_LIMIT = 2 * 1024 * 1024


# mosp's own routes take small bodies, whatever the application allows
# elsewhere: credentials, and second-factor documents carrying certificates.
CREDENTIAL_BODY_LIMIT = 16 * 1024
SECOND_FACTOR_BODY_LIMIT = 256 * 1024


def body_limit(path: str) -> int:
    """The largest request body accepted on ``path``: mosp's limit for its own
    sign-in, password and second-factor routes, the application's otherwise."""
    if path in {"/v1/auth/login", "/v1/me/password"}:
        return CREDENTIAL_BODY_LIMIT
    if path.startswith("/v1/auth/mfa/"):
        return SECOND_FACTOR_BODY_LIMIT
    hook = _hook("body_limit")
    return DEFAULT_BODY_LIMIT if hook is None else int(hook(path))


def encoded_slash_routes() -> Any:
    """A compiled pattern of the paths whose last parameter may hold an
    encoded "/" (default: none)."""
    hook = _hook("encoded_slash_routes")
    return None if hook is None else hook()


def measured_fields() -> dict[str, str]:
    """Field names that hold a measured boolean, count or timestamp although
    they contain a sensitive-key substring (default: none)."""
    hook = _hook("measured_fields")
    return {} if hook is None else hook()


def issued_secret_pattern() -> Any:
    """A compiled pattern of tokens the application issues, redacted wherever
    they appear (default: none)."""
    hook = _hook("issued_secret_pattern")
    return None if hook is None else hook()


def route_policy() -> Any:
    """The application's routes in the route policy
    (``mosp.security.route_policy.RoutePolicy``; default: none)."""
    hook = _hook("route_policy")
    return None if hook is None else hook()


def json_body_limit(path: str) -> int:
    """The most JSON parsed from one request to ``path`` (default: the route's
    body limit)."""
    hook = _hook("json_body_limit")
    return body_limit(path) if hook is None else int(hook(path))


DEFAULT_JSON_VALUES = 20_000


def json_value_limit(path: str) -> int | None:
    """The most values a JSON request to ``path`` may hold; None for no bound."""
    hook = _hook("json_value_limit")
    return DEFAULT_JSON_VALUES if hook is None else hook(path)


class NotInner:
    """The answer of ``inner_request_user`` for a request from outside."""


NOT_INNER = NotInner()


def inner_request_user(db: Any, request: Any) -> Any:
    """The account an in-process request acts as (an MCP tool's, say): an
    account, a refusal response, None when its credential is not current, or
    NOT_INNER for an ordinary request (default: every request is ordinary)."""
    hook = _hook("inner_request_user")
    return NOT_INNER if hook is None else hook(db, request)


def audit_path(path: str) -> str:
    """A request path as the audit trail keeps it (default: as requested).

    An application whose paths can carry a credential, such as a share link's
    token, returns the path with it masked."""
    hook = _hook("audit_path")
    return path if hook is None else hook(path)


def bootstrap_allowed() -> bool:
    """Whether the first administrator may come from the bootstrap settings
    (default: yes)."""
    hook = _hook("bootstrap_allowed")
    return True if hook is None else bool(hook())


# The browser pages mosp's routes and messages send people to.
DEFAULT_PAGES = {
    "home": "/",
    "sign_in": "/login.html",
    "account": "/account.html",
    "second_factor": "/mfa.html",
    "sso_email": "/sso-email.html",
}


def page(name: str) -> str:
    """The path of one of the application's pages (default: DEFAULT_PAGES).

    The application's ``pages`` hook returns the paths it changes; the rest
    keep their defaults.
    """
    hook = _hook("pages")
    own = {} if hook is None else hook()
    return own.get(name) or DEFAULT_PAGES[name]
