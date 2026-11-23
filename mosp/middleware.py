"""The request path every application shares: authentication, CSRF and Origin
checks, the write policy and the request audit trail, plus the first
administrator's bootstrap.

``install(app)`` registers the middleware in the order it must run: the audit
trail outermost, then authentication, then CSRF (Starlette runs the last
middleware declared first).
"""

from __future__ import annotations

import logging
import time
from typing import cast
from urllib.parse import urlsplit, urlunsplit

import anyio
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from redis.exceptions import RedisError
from sqlalchemy import String
from starlette.concurrency import run_in_threadpool

from mosp import host
from mosp.api.context import machine_credential
from mosp.core.datetime_utils import utc_now_naive
from mosp.core.valkey import get_valkey
from mosp.host import hooks
from mosp.host.config import settings
from mosp.host.db import SessionLocal
from mosp.host.models import AuditLog, User
from mosp.security.auth import ROLE_ADMIN, create_user, get_current_user_from_request
from mosp.security.client_ip import request_ip
from mosp.security.csrf import (
    csrf_valid,
    generate_csrf_token,
    get_csrf_token_from_request,
    request_origin_allowed,
    set_csrf_cookie,
)
from mosp.security.permissions import (
    ensure_session_authorization_current,
    has_permission,
)
from mosp.security.placeholders import is_placeholder
from mosp.security.rate_limit import address_window_allow
from mosp.security.redaction import redact_query_string, redact_str
from mosp.security.regex import scan_pattern
from mosp.security.roles import attach_effective_role, lock_admin_changes
from mosp.security.route_policy import (
    UNSAFE_METHODS,
    admin_only,
    gated_write_permission,
    is_admin_write,
    is_permission_checked_write,
    is_public_request,
    is_self_service_write,
    policy,
    policy_path,
    prefix_rule,
    refuses_undeclared_writes,
)

log = logging.getLogger(__name__)


async def csrf_middleware(request: Request, call_next):
    """Double-submit cookie CSRF protection for the web UI.

    The UI uses a cookie-backed session (HttpOnly) and echoes a CSRF token from
    a non-HttpOnly cookie into a request header for all unsafe methods.
    """
    if is_public_request(request):
        # A browser sends every write from the application's own origin,
        # including the public ones (signing in or out, a second factor in
        # progress, and any route added to the public list later), which have
        # no session to bind a CSRF token to. Machine clients send no Origin.
        # Signed-in writes are checked with their CSRF token below.
        if request.method.upper() in UNSAFE_METHODS and not request_origin_allowed(
            request
        ):
            return JSONResponse(
                {"detail": "Authentication request origin is not allowed"},
                status_code=403,
            )
        return await call_next(request)

    # Only enforce CSRF for authenticated browser sessions. An in-process
    # request (an MCP tool's) carries its credential in the ASGI scope, which
    # no browser can set, and no cookie.
    user = getattr(request.state, "user", None)
    inner = getattr(request.state, "inner_client", None) is not None
    if user and not inner and request.method.upper() in UNSAFE_METHODS:
        if not csrf_valid(request):
            return JSONResponse(
                {"detail": "CSRF token missing or invalid"}, status_code=403
            )

    response = await call_next(request)

    # Browsers signed in by a trusted proxy have no sign-in response to carry
    # the CSRF cookie, and a browser may lose the cookie before its session
    # ends; either receives a token with this response: the session's own
    # where it holds one.
    if user and not inner and not get_csrf_token_from_request(request):
        try:
            set_csrf_cookie(response, user.session_csrf or generate_csrf_token())
        except Exception:
            # CSRF cookie minting should never break the main request path.
            pass

    return response


async def auth_middleware(request: Request, call_next):
    """Authenticate the request and attach request.state.user.

    It runs before ``csrf_middleware`` (``install`` declares it after), so
    request.state.user is populated when CSRF enforcement happens.
    """
    if is_public_request(request):
        return await call_next(request)

    # Database and session-store work runs in the thread pool, so one slow
    # lookup never holds up the requests the event loop is serving.
    refused = await run_in_threadpool(authenticate, request)
    if refused is not None:
        return refused
    return await call_next(request)


def authenticate(request: Request) -> JSONResponse | None:
    """Attach the request's user, or return the response refusing the request."""
    path = policy_path(request)

    # The user is loaded in a short-lived session, checked, detached and the
    # session closed before the route runs: route handlers open their own
    # sessions, and an instance still attached to this one could not be used
    # with them.
    db = SessionLocal()
    user = None
    try:
        found = hooks.inner_request_user(db, request)
        if found is hooks.NOT_INNER:
            try:
                user = get_current_user_from_request(request, db)
            except (RedisError, OSError):
                # Without the session store nobody can be recognised; say so
                # as an outage, as sign-in does, and name no account.
                return JSONResponse(
                    {
                        "detail": "Service temporarily unavailable. "
                        "Please try again later."
                    },
                    status_code=503,
                    headers={"Retry-After": "5"},
                )
        elif isinstance(found, JSONResponse):
            return found
        else:
            user = found
        if not user:
            return JSONResponse({"detail": "Not authenticated"}, status_code=401)
        # The audit trail names the account even when a check below refuses it;
        # closing the session detaches the instance on those early returns.
        request.state.user = user

        # Use the server-side session permission snapshot when current. This
        # keeps page rendering from querying RBAC tables on every navigation
        # while remaining invalidatable by administrators' RBAC changes.
        ensure_session_authorization_current(db, user)
        effective_role = user.effective_role or attach_effective_role(db, user)

        if admin_only(request.method, path) and effective_role != ROLE_ADMIN:
            return JSONResponse({"detail": "Admin role required"}, status_code=403)

        # Default rule: only administrators change state, except for the
        # writes the route policy assigns elsewhere.
        if request.method.upper() in UNSAFE_METHODS:
            refusal = _write_refusal(db, request, user, effective_role)
            if refusal is not None:
                return refusal

        # Detach the instance so it can be safely used with other sessions.
        db.expunge(user)
        request.state.user = user
    finally:
        db.close()
    return None


def _write_refusal(db, request: Request, user, effective_role) -> JSONResponse | None:
    path = policy_path(request)
    if is_permission_checked_write(request) or is_self_service_write(request):
        # Authentication and CSRF still apply; the route enforces the rest.
        return None
    if code := gated_write_permission(request):
        if has_permission(db, user, code):
            return None
        return JSONResponse({"detail": f"{code} permission required"}, status_code=403)
    if rule := prefix_rule(path):
        if any(has_permission(db, user, code) for code in rule.permissions):
            return None
        return JSONResponse({"detail": rule.refusal()}, status_code=403)
    if is_admin_write(request):
        if effective_role == ROLE_ADMIN:
            return None
        return JSONResponse({"detail": "Admin role required"}, status_code=403)
    if refuses_undeclared_writes():
        return JSONResponse(
            {"detail": "This route accepts no changes"}, status_code=403
        )
    if effective_role != ROLE_ADMIN:
        return JSONResponse(
            {"detail": "Read-only users cannot perform write actions"},
            status_code=403,
        )
    return None


# Authorisation codes and state are single-use, but are still credentials
# while a sign-in is in progress; keep them out of the audit trail.
_OAUTH_CALLBACK_PATH = scan_pattern(r"/v1/auth/(?:oidc|sso/[^/]+)/callback")
_OAUTH_CALLBACK_QUERY_KEYS = frozenset({"code", "state"})
# Requests without a signed-in account or a verified machine credential carry
# no identity, so each client address (each /64 network for IPv6) adds at most
# this many such records a minute, whatever their status: refusals, and public
# routes that succeed without a credential, such as signing out.
ANONYMOUS_AUDIT_LIMIT = 60


def _audits_anonymous_request(client_ip: str | None) -> bool:
    # Fails closed: while Valkey is unavailable these requests cannot be
    # counted, so they go unrecorded and cannot fill the database.
    allowed, _ = address_window_allow(
        get_valkey(),
        "audit-anonymous",
        client_ip,
        ANONYMOUS_AUDIT_LIMIT,
        60,
        fail_closed=True,
    )
    return allowed


async def audit_trail_middleware(request: Request, call_next):
    """Persist an audit trail of API requests.

    Records are written after the response completes so we can capture status
    codes and timings.
    """
    path = policy_path(request)
    current = policy()
    if (
        not path.startswith("/v1")
        or path in current.unaudited_paths
        or (request.method == "GET" and path in current.unaudited_public_reads)
    ):
        return await call_next(request)

    start = time.perf_counter()
    response = None

    try:
        response = await call_next(request)
        return response
    finally:
        status_code = getattr(response, "status_code", 500)
        dur_ms = int((time.perf_counter() - start) * 1000)
        try:
            # The record is written in the thread pool, off the event loop, and
            # is kept even when the client goes away before it is written.
            with anyio.CancelScope(shield=True):
                await run_in_threadpool(
                    record_request, request, path, status_code, dur_ms
                )
        except Exception as error:
            # Audit logging must never break the main request path. The loss
            # is logged without anything the request carried.
            log.warning(
                "A request audit record could not be written (%s)",
                type(error).__name__,
            )


def _referer_for_audit(value: str | None) -> str | None:
    """The page a request came from, as the audit trail keeps it: its path
    masked as the request's own is, its query redacted, without a fragment,
    and any credential left in it redacted."""
    text = (value or "").strip()
    if not text:
        return None
    try:
        parts = urlsplit(text)
    except ValueError:
        return None
    kept = urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            hooks.audit_path(parts.path),
            redact_query_string(parts.query) or "",
            "",
        )
    )
    return redact_str(kept) or None


def record_request(request: Request, path: str, status_code: int, dur_ms: int):
    user = getattr(request.state, "user", None)
    username = getattr(user, "username", None) if user else None
    client_ip = request_ip(request)

    if not (
        username is not None
        or machine_credential(request) is not None
        or _audits_anonymous_request(client_ip)
    ):
        return
    qs = redact_query_string(
        request.url.query,
        _OAUTH_CALLBACK_QUERY_KEYS
        if _OAUTH_CALLBACK_PATH.fullmatch(path)
        else frozenset(),
    )
    if qs and len(qs) > 4096:
        qs = qs[:4096]

    ua = (request.headers.get("user-agent") or "").strip() or None
    ref = _referer_for_audit(request.headers.get("referer"))

    # Truncate potentially long strings for safety.
    if ua and len(ua) > 256:
        ua = ua[:256]
    if ref and len(ref) > 512:
        ref = ref[:512]
    # Every value the caller chooses is cut to its column's width: one the
    # column refused would cost the whole record, and the request would be
    # served without a trace.
    columns = AuditLog.__table__.c
    method = request.method[: cast(String, columns.method.type).length]
    # The application masks what a path carries that grants access (a share
    # link's token, say) before the path is kept.
    path = hooks.audit_path(path)[: cast(String, columns.path.type).length]

    db = SessionLocal()
    try:
        db.add(
            AuditLog(
                ts=utc_now_naive(),
                username=username,
                method=method,
                path=path,
                query_string=qs,
                status_code=int(status_code or 0),
                duration_ms=dur_ms,
                client_ip=client_ip,
                user_agent=ua,
                referer=ref,
            )
        )
        db.commit()
    finally:
        db.close()


def bootstrap_initial_admin():
    """Create the first administrator on a fresh installation.

    When the bootstrap username and password settings are both set and there
    are no users in the database, create an initial administrator.
    """
    if not hooks.bootstrap_allowed():
        return
    uname = settings.bootstrap_admin_username.strip()
    pwd = settings.bootstrap_admin_password.strip()
    if not uname and not pwd:
        return  # Explicit bootstrap is optional; no account is created.

    db = SessionLocal()
    try:
        # API worker processes start together; one creates the account while
        # the others wait, then find it.
        lock_admin_changes(db)
        if db.query(User).count() > 0:
            return
        if not uname or not pwd:
            raise ValueError(
                "Supply both bootstrap credentials for initial account creation"
            )
        if is_placeholder(pwd):
            raise ValueError("Replace the placeholder bootstrap password")
        # The password meets the rules every new password does.
        create_user(db, username=uname, password=pwd, role=ROLE_ADMIN)
        print(f"[{host.name()}] Bootstrapped initial admin user: {uname}")
    except Exception:
        # Do not expose passwords or database diagnostics in startup failures.
        db.rollback()
        raise RuntimeError(
            "Initial administrator creation failed; on an empty installation supply "
            f"both {host.env('BOOTSTRAP_ADMIN_USERNAME')} and "
            f"{host.env('BOOTSTRAP_ADMIN_PASSWORD')} "
            f"(at least {settings.password_min_length} characters, hard to guess, "
            "and never an example file's placeholder), and check database "
            "availability"
        ) from None
    finally:
        db.close()


def install(app: FastAPI) -> None:
    """Register mosp's request middleware on ``app``.

    Starlette runs the last middleware declared first: the audit trail sees
    every request and its outcome, authentication attaches the account, and
    the CSRF check then sees it.
    """
    app.middleware("http")(csrf_middleware)
    app.middleware("http")(auth_middleware)
    app.middleware("http")(audit_trail_middleware)
