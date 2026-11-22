"""Points where myf asks the application to take part.

An application defines any of these functions in the module it binds to the
``hooks`` role; a hook it leaves out keeps myf's default. Hooks are looked up
on every call, so an application can import lazily inside its own hooks.
"""

from __future__ import annotations

from typing import Any

from myf.host import _bound, module


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


def route_class() -> type:
    """The route class myf's routers use, so the application's error contract
    and per-route dependencies apply to them (default: FastAPI's APIRoute)."""
    hook = _hook("route_class")
    if hook is None:
        from fastapi.routing import APIRoute

        return APIRoute
    return hook()


def security_notice(event: str) -> tuple[str, str] | None:
    """The title and explanation of a security notice the application adds
    (an event myf does not send itself); None for myf's own events."""
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


def body_limit(path: str) -> int:
    """The largest request body the application accepts on ``path``."""
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
