"""Bearer API tokens: another application's reads, as one account.

An administrator issues a token for one account (``mosp.services.api_tokens``)
and gives it to the application that will read, which sends it as
``Authorization: Bearer <token>``. A request carrying one acts as that account
with its current role and permissions, for reads only, and only on the routes
the route policy lists in ``token_reads``; every other request carrying one is
refused before any route runs. Cookies on such a request are ignored, so a
token never stands in for a browser session or the reverse.

A token is ``<name>_at_`` followed by 43 random URL-safe characters (256 bits).
The application keeps only its SHA-256 digest; the token is shown once, when
it is issued. Tokens are accepted only while the installation turns them on
(``<NAME>_API_TOKENS_ENABLED``, off by default). A token stops working when it is revoked, when it expires, when its
account is removed or inactive, and whenever the application declares no
``ApiToken`` model (``mosp.db.accounts.ApiTokenMixin``), which is how an
application that accepts no tokens leaves this module inert. A request whose
``Authorization`` header carries any other kind of credential is not this
module's to judge, and passes on as before.

An application deactivating an account revokes its tokens in the same
transaction (``mosp.services.api_tokens.revoke_for_account``), so they stay
revoked if the account is activated again. The account's own credentials are
another matter: a password change, a second-factor change or an SSO identity
removed leaves its tokens as they are; revoking or expiring a token is what
ends it.

Each token has its own allowance of reads a minute, counted only after the
token verifies, so a client without it cannot spend it. Tokens are redacted
wherever redaction applies (``mosp.security.redaction``).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy import update
from sqlalchemy.orm import Session

from mosp import host
from mosp.api.context import mark_machine_credential
from mosp.core.datetime_utils import utc_now_naive
from mosp.core.valkey import get_valkey
from mosp.host import models
from mosp.host.config import settings
from mosp.security.api_token_format import digest, pattern, prefix
from mosp.security.rate_limit import fixed_window_allow
from mosp.security.roles import is_active_user
from mosp.security.route_policy import is_token_read

# Reads one token may make each minute.
READS_PER_MINUTE = 600
# How often a token's last use is written: a busy token costs one row update a
# minute, not one a request.
LAST_USED_INTERVAL = timedelta(minutes=1)
# The request state attribute naming the token that verified a request.
STATE = "api_token"


def enabled() -> bool:
    """Whether the installation accepts API tokens: its
    ``<NAME>_API_TOKENS_ENABLED`` setting is on (it is off by default) and the
    application declares the ``ApiToken`` model."""
    if not settings.api_tokens_enabled:
        return False
    try:
        models.ApiToken
    except AttributeError:
        return False
    return True


def presented(request: Request) -> str | None:
    """The API token a request presents, or None when it presents none.

    A bearer credential with the application's token prefix is an API token
    whatever follows the prefix; ``authenticate`` refuses one that is not well
    formed. A request carrying more than one Authorization header with such a
    credential among them presents an empty token, which is refused, so no
    reading of a duplicated header decides who the request is.
    """
    if not enabled():
        return None
    ours = prefix()
    found = []
    for value in request.headers.getlist("authorization"):
        scheme, _, credential = value.strip().partition(" ")
        if scheme.lower() == "bearer" and credential.strip().startswith(ours):
            found.append(credential.strip())
    if not found:
        return None
    if len(found) != 1 or len(request.headers.getlist("authorization")) != 1:
        return ""
    return found[0]


def _not_authenticated() -> JSONResponse:
    return JSONResponse(
        {"detail": "Not authenticated"},
        status_code=401,
        headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
    )


def authenticate(db: Session, request: Request, value: str) -> Any:
    """The account a token-bearing request acts as, or the response refusing it.

    Every refusal of the token itself is the same 401, whether the token is
    malformed, unknown, revoked, expired or its account inactive.
    """
    if not is_token_read(request):
        return JSONResponse(
            {"detail": "API tokens reach only the routes listed for them"},
            status_code=403,
        )
    if not pattern().fullmatch(value):
        return _not_authenticated()
    ApiToken = models.ApiToken
    row = db.query(ApiToken).filter(ApiToken.token_hash == digest(value)).first()
    now = utc_now_naive()
    if (
        row is None
        or row.revoked_at is not None
        or (row.expires_at is not None and row.expires_at <= now)
    ):
        return _not_authenticated()
    user = db.get(models.User, row.user_id)
    if not is_active_user(user):
        return _not_authenticated()
    allowed, retry_after = fixed_window_allow(
        get_valkey(),
        f"{host.name()}:rl:api-token:{row.id}",
        READS_PER_MINUTE,
        60,
        fail_closed=True,
    )
    if not allowed:
        return JSONResponse(
            {"detail": "Too many requests with this API token"},
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )
    if row.last_used_at is None or now - row.last_used_at >= LAST_USED_INTERVAL:
        # Conditional, so concurrent requests write it once.
        db.execute(
            update(ApiToken)
            .where(
                ApiToken.id == row.id,
                (ApiToken.last_used_at.is_(None))
                | (ApiToken.last_used_at <= now - LAST_USED_INTERVAL),
            )
            .values(last_used_at=now)
        )
        db.commit()
        # The account is read again after the commit, as the route will see it.
        db.refresh(user)
    setattr(request.state, STATE, str(row.id))
    mark_machine_credential(request, f"api-token:{row.id}")
    return user


def verified_token(request: Request) -> str | None:
    """The id of the API token that verified this request, if one did."""
    return getattr(request.state, STATE, None)
