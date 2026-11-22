"""Which requests skip sign-in, and which writes a signed-in account may make.

Every HTTP route is authenticated unless the policy names it public. A public
entry applies only to its method and complete path shape: a new route under
``/v1/auth`` inherits nothing. Every write by a signed-in account needs an
administrator unless the policy says otherwise, so a new write route fails
closed until its rule is written.

myf declares the routes it serves itself (``MYF_POLICY``); an application adds
its own through ``hooks.route_policy`` and both apply together.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from starlette.routing import compile_path

from myf.host import hooks

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _methods(routes: Mapping[str, Iterable[str]]) -> dict[str, tuple[str, ...]]:
    return {method.upper(): tuple(paths) for method, paths in routes.items()}


@dataclass(frozen=True, eq=False)
class RouteSet:
    """Path templates by method, matched against the routed path."""

    routes: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        routes = _methods(self.routes)
        object.__setattr__(self, "routes", routes)
        object.__setattr__(
            self,
            "_compiled",
            {
                method: tuple(compile_path(path)[0] for path in paths)
                for method, paths in routes.items()
            },
        )

    def matches(self, method: str, path: str) -> bool:
        return any(
            pattern.fullmatch(path)
            for pattern in self._compiled.get(method.upper(), ())  # type: ignore[attr-defined]
        )

    def __or__(self, other: RouteSet) -> RouteSet:
        merged = {method: list(paths) for method, paths in self.routes.items()}
        for method, paths in other.routes.items():
            merged.setdefault(method, []).extend(paths)
        return RouteSet({method: tuple(paths) for method, paths in merged.items()})


@dataclass(frozen=True, eq=False)
class RouteCodes:
    """A value (a permission or scope) for each method and path template."""

    entries: Mapping[tuple[str, str], str | None] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "_compiled",
            tuple(
                (method.upper(), compile_path(path)[0], code)
                for (method, path), code in self.entries.items()
            ),
        )

    def lookup(self, method: str, path: str, default=None):
        for allowed, pattern, code in self._compiled:  # type: ignore[attr-defined]
            if method.upper() == allowed and pattern.fullmatch(path):
                return code
        return default

    def __or__(self, other: RouteCodes) -> RouteCodes:
        return RouteCodes({**self.entries, **other.entries})


@dataclass(frozen=True)
class PrefixRule:
    """Writes under ``prefix`` need one of ``permissions``; ``message`` names the
    refusal when it should say more (or less) than the permissions."""

    prefix: str
    permissions: tuple[str, ...]
    message: str | None = None

    def refusal(self) -> str:
        return self.message or f"{' or '.join(self.permissions)} permission required"


@dataclass(frozen=True, eq=False)
class RoutePolicy:
    # Routes reachable without a session; each authenticates what it needs.
    public: RouteSet = field(default_factory=RouteSet)
    # Writes any signed-in account makes for itself.
    self_service: RouteSet = field(default_factory=RouteSet)
    self_service_prefixes: tuple[str, ...] = ()
    # Writes whose route checks the account's permissions itself.
    object_checked: RouteSet = field(default_factory=RouteSet)
    # Writes the middleware gates on one permission before the route runs.
    gated: RouteCodes = field(default_factory=RouteCodes)
    # Writes under a prefix that need one of a set of permissions.
    prefix_rules: tuple[PrefixRule, ...] = ()
    # Namespaces only administrators reach, reads included.
    admin_prefixes: tuple[str, ...] = ()
    # Paths whose requests the audit trail leaves out, and public reads it
    # leaves out (documents anyone may fetch at any rate).
    unaudited_paths: frozenset[str] = frozenset()
    unaudited_public_reads: frozenset[str] = frozenset()

    def __or__(self, other: RoutePolicy) -> RoutePolicy:
        return RoutePolicy(
            public=self.public | other.public,
            self_service=self.self_service | other.self_service,
            self_service_prefixes=self.self_service_prefixes
            + other.self_service_prefixes,
            object_checked=self.object_checked | other.object_checked,
            gated=self.gated | other.gated,
            prefix_rules=self.prefix_rules + other.prefix_rules,
            admin_prefixes=self.admin_prefixes + other.admin_prefixes,
            unaudited_paths=self.unaudited_paths | other.unaudited_paths,
            unaudited_public_reads=self.unaudited_public_reads
            | other.unaudited_public_reads,
        )


# The routes myf serves (myf.api.routes): signing in and out, single sign-on,
# second-factor ceremonies, and the account's own SSO addresses. Second-factor
# routes validate a pending ceremony and the request's Origin themselves.
MYF_POLICY = RoutePolicy(
    public=RouteSet(
        {
            "GET": (
                "/v1/auth/methods",
                "/v1/auth/logout",
                "/v1/auth/oidc/start",
                "/v1/auth/oidc/callback",
                "/v1/auth/oidc/logout",
                "/v1/auth/sso/{provider_key}/start",
                "/v1/auth/sso/{provider_key}/callback",
            ),
            "POST": (
                "/v1/auth/oidc/logout",
                "/v1/auth/login",
                "/v1/auth/logout",
                "/v1/auth/mfa/manage/start",
                "/v1/auth/mfa/state",
                "/v1/auth/mfa/verify-code",
                "/v1/auth/mfa/totp/start",
                "/v1/auth/mfa/totp/confirm",
                "/v1/auth/mfa/webauthn/options",
                "/v1/auth/mfa/webauthn/verify",
                "/v1/auth/mfa/webauthn/register-options",
                "/v1/auth/mfa/webauthn/register",
                "/v1/auth/mfa/remove",
                "/v1/auth/mfa/recovery/regenerate",
                "/v1/auth/mfa/finish",
                "/v1/auth/mfa/cancel",
            ),
        }
    ),
    # Any write to these is the account's own.
    self_service=RouteSet(
        dict.fromkeys(
            UNSAFE_METHODS,
            (
                "/v1/auth/logout",
                "/v1/me/sso-emails/request",
                "/v1/me/sso-emails/confirm",
                "/v1/me/sso-emails/remove",
            ),
        )
    ),
    unaudited_public_reads=frozenset({"/v1/auth/methods"}),
)

_merged: tuple[object, RoutePolicy] | None = None


def policy() -> RoutePolicy:
    """myf's policy with the application's own (``hooks.route_policy``)."""
    global _merged
    own = hooks.route_policy()
    if _merged is None or _merged[0] is not own:
        _merged = (own, MYF_POLICY if own is None else MYF_POLICY | own)
    return _merged[1]


def policy_path(request) -> str:
    """The decoded path the router dispatches on.

    ``request.url.path`` is re-parsed from a URL string, so an encoded ``?`` or
    ``#`` inside a path parameter truncates it. Policy must use the routed path.
    """
    return request.scope.get("path") or ""


def is_public_request(request) -> bool:
    return policy().public.matches(request.method, policy_path(request))


def is_permission_checked_write(request) -> bool:
    return policy().object_checked.matches(request.method, policy_path(request))


def gated_write_permission(request) -> str | None:
    """The permission the middleware requires for this write, if any."""
    return policy().gated.lookup(request.method, policy_path(request))


def is_self_service_write(request) -> bool:
    current = policy()
    path = policy_path(request)
    return current.self_service.matches(request.method, path) or any(
        path.startswith(prefix) for prefix in current.self_service_prefixes
    )


def admin_only(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in policy().admin_prefixes)


def prefix_rule(path: str) -> PrefixRule | None:
    for rule in policy().prefix_rules:
        if path.startswith(rule.prefix):
            return rule
    return None
