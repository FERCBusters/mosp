"""Issuing, listing and revoking API tokens (``mosp.security.api_tokens``).

Tokens are issued only while the installation turns them on
(``<NAME>_API_TOKENS_ENABLED``); listing and revoking work either way, so
tokens issued earlier can be reviewed and revoked. Only administrators reach
these operations (``mosp.api.routes.api_tokens``,
under ``/v1/admin/api-tokens``). A token acts as the account it is issued
for, so that account's holder is sent a security notice whenever one is
issued or revoked; an account may hold a bounded number of current tokens.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import NamedTuple

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from mosp import host
from mosp.core.datetime_utils import iso_utc, utc_now_naive
from mosp.core.identifiers import try_uuid
from mosp.host.models import ApiToken, User
from mosp.security import api_token_format, api_tokens
from mosp.services import security_notifications
from mosp.services.context import ChangeContext
from mosp.services.errors import DomainError
from mosp.services.text import clean_text

# Current (unrevoked, unexpired) tokens one account may hold.
MAX_CURRENT_PER_ACCOUNT = 10
MAX_LIFETIME_DAYS = 366
# The listing shows the most recent tokens.
MAX_LISTED = 500


class ApiTokenPayload(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    user_id: str = Field(min_length=1, max_length=64)
    # None issues a token that does not expire.
    expires_in_days: int | None = Field(default=None, ge=1, le=MAX_LIFETIME_DAYS)


class _Account(NamedTuple):
    username: str
    active: bool


def _status(row: ApiToken, accounts: dict[uuid.UUID, _Account], now) -> str:
    if row.revoked_at is not None:
        return "revoked"
    if row.expires_at is not None and row.expires_at <= now:
        return "expired"
    if not accounts[row.user_id].active:
        # Refused while its account is inactive.
        return "inactive"
    return "active"


def _out(row: ApiToken, accounts: dict[uuid.UUID, _Account], now) -> dict:
    names = {key: account.username for key, account in accounts.items()}
    return {
        "id": str(row.id),
        "name": row.name,
        "user_id": str(row.user_id),
        "username": names.get(row.user_id),
        "hint": row.hint,
        "created_at": iso_utc(row.created_at),
        "created_by": names.get(row.created_by_user_id)
        if row.created_by_user_id
        else None,
        "expires_at": iso_utc(row.expires_at),
        "last_used_at": iso_utc(row.last_used_at),
        "revoked_at": iso_utc(row.revoked_at),
        "status": _status(row, accounts, now),
    }


def _accounts(db: Session, rows: list[ApiToken]) -> dict[uuid.UUID, _Account]:
    ids = {row.user_id for row in rows} | {
        row.created_by_user_id for row in rows if row.created_by_user_id
    }
    if not ids:
        return {}
    found = db.query(User.id, User.username, User.is_active).filter(User.id.in_(ids))
    return {
        user_id: _Account(username, is_active) for user_id, username, is_active in found
    }


def list_tokens(db: Session) -> dict:
    rows = (
        db.query(ApiToken)
        .order_by(ApiToken.created_at.desc(), ApiToken.id)
        .limit(MAX_LISTED)
        .all()
    )
    accounts = _accounts(db, rows)
    now = utc_now_naive()
    return {
        "enabled": api_tokens.enabled(),
        "items": [_out(row, accounts, now) for row in rows],
    }


def _notice_detail(row: ApiToken, actor: User) -> str:
    return (
        f"Token: {row.name} (ending {row.hint})\n"
        f"By administrator: {actor.username}\n"
        f"Expires: {iso_utc(row.expires_at) or 'never'}"
    )


def issue_token(
    db: Session, *, payload: ApiTokenPayload, actor: User, context: ChangeContext
) -> dict:
    """Issue a token for the named account; the token is returned only here."""
    if not api_tokens.enabled():
        raise DomainError(
            409,
            f"API tokens are turned off for this installation "
            f"({host.env('API_TOKENS_ENABLED')})",
        )
    name = clean_text(
        payload.name, max_len=100, required=True, label="Token name", single_line=True
    )
    user_id = try_uuid(payload.user_id)
    # The account's row is locked while its current tokens are counted, so
    # concurrent issues cannot pass the limit together.
    user = (
        db.query(User).filter(User.id == user_id).with_for_update().one_or_none()
        if user_id is not None
        else None
    )
    if user is None or not user.is_active:
        raise DomainError(404, "Active account not found")
    now = utc_now_naive()
    current = (
        db.query(ApiToken.id)
        .filter(
            ApiToken.user_id == user.id,
            ApiToken.revoked_at.is_(None),
            (ApiToken.expires_at.is_(None)) | (ApiToken.expires_at > now),
        )
        .count()
    )
    if current >= MAX_CURRENT_PER_ACCOUNT:
        raise DomainError(
            409,
            f"An account holds at most {MAX_CURRENT_PER_ACCOUNT} current API "
            "tokens; revoke one first",
        )
    value, token_hash = api_token_format.issue()
    row = ApiToken(
        user_id=user.id,
        name=name,
        token_hash=token_hash,
        hint=value[-4:],
        created_by_user_id=actor.id,
        created_at=now,
        expires_at=(
            now + timedelta(days=payload.expires_in_days)
            if payload.expires_in_days
            else None
        ),
    )
    db.add(row)
    db.flush()
    security_notifications.enqueue(
        db,
        user,
        "api-token-issued",
        ip=context.client_ip,
        detail=_notice_detail(row, actor),
    )
    db.commit()
    return {
        "token": value,
        "item": _out(row, _accounts(db, [row]), now),
    }


def revoke_token(
    db: Session, *, token_id: str, actor: User, context: ChangeContext
) -> dict:
    parsed = try_uuid(token_id)
    row = (
        db.query(ApiToken).filter(ApiToken.id == parsed).with_for_update().one_or_none()
        if parsed is not None
        else None
    )
    if row is None:
        raise DomainError(404, "API token not found")
    now = utc_now_naive()
    if row.revoked_at is None:
        row.revoked_at = now
        # The token goes with its account, so the account is still there.
        owner = db.query(User).filter(User.id == row.user_id).one()
        security_notifications.enqueue(
            db,
            owner,
            "api-token-revoked",
            ip=context.client_ip,
            detail=_notice_detail(row, actor),
        )
        db.commit()
    return {"item": _out(row, _accounts(db, [row]), now)}


def revoke_for_account(db: Session, user: User) -> int:
    """Revoke every token of ``user`` that is not revoked already, in the
    caller's transaction; the number revoked.

    An application calls this wherever it deactivates an account, so the
    account's tokens stay revoked if it is activated again. No notice is
    sent: the account's holder is no longer signing in.
    """
    return (
        db.query(ApiToken)
        .filter(ApiToken.user_id == user.id, ApiToken.revoked_at.is_(None))
        .update({ApiToken.revoked_at: utc_now_naive()}, synchronize_session=False)
    )
