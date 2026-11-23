"""An account's own password: changing it, and what a new password ends."""

from __future__ import annotations

from sqlalchemy.orm import Session

from myf import host
from myf.api.schemas import ChangePasswordPayload
from myf.core.valkey import get_valkey
from myf.host.config import settings
from myf.host.models import User
from myf.security.passwords import hash_password, verify_password
from myf.security.rate_limit import address_window_allow, fixed_window_allow
from myf.services.context import ChangeContext, signed_in_user
from myf.services.errors import DomainError


def _within_allowances(context: ChangeContext, user: User) -> None:
    """Refuse a change past the address's or the account's allowance.

    Both fail closed: without the store, no change is attempted.
    """
    try:
        r = get_valkey()
        window = settings.login_rate_limit_window_seconds
        ok, _ = address_window_allow(
            r,
            "password_change",
            context.client_ip,
            settings.login_rate_limit_per_ip,
            window,
            fail_closed=True,
        )
        # A session holder must not be able to test many current passwords by
        # spreading attempts across addresses.
        if ok:
            ok, _ = fixed_window_allow(
                r,
                f"{host.name()}:rl:password_change:user:{user.id}",
                settings.password_change_rate_limit_per_account,
                window,
                fail_closed=True,
            )
    except Exception:
        raise DomainError(
            status_code=503,
            detail="Service temporarily unavailable. Please try again later.",
        ) from None
    if not ok:
        raise DomainError(
            status_code=429,
            detail="Too many password change attempts. Please try again later.",
        )


def change_password(
    *, payload: ChangePasswordPayload, context: ChangeContext, db: Session
) -> dict:
    """Change the signed-in account's password after checking its current one.

    The change ends the account's other sessions (its second-factor version
    moves on), ends every browser's recognition and tells the account holder.
    """
    user = signed_in_user(context)
    _within_allowances(context, user)

    if user.auth_backend == "ldap":
        raise DomainError(403, "Change your password in your LDAP directory")
    # Behind an authenticating proxy, the proxy's identity provider holds the
    # password.
    if settings.trust_remote_user:
        raise DomainError(
            status_code=403,
            detail="Password changes are disabled when "
            f"{host.env('TRUST_REMOTE_USER')} is enabled",
        )

    user = (
        db.query(User)
        .filter(User.id == user.id)
        .populate_existing()
        .with_for_update()
        .one()
    )
    if not verify_password(payload.current_password or "", user.password_hash):
        raise DomainError(status_code=400, detail="Current password is incorrect")

    try:
        user.password_hash = hash_password(
            payload.new_password or "", username=user.username
        )
    except ValueError as error:
        raise DomainError(status_code=400, detail=str(error)) from None
    user.mfa_version += 1

    from myf.services.security_notifications import enqueue

    enqueue(db, user, "password-changed", ip=context.client_ip)
    db.add(user)
    db.commit()
    end_password_recognition(str(user.id))
    return {"ok": True}


def end_password_recognition(user_id: str, *, key: str | None = None) -> None:
    """A changed or reset password ends every browser's recognition for the
    account; a reset also clears the sign-in throttle kept under ``key``, the
    account's ``myf.services.login.sign_in_key``.

    Each browser is recognised again after its next correct password. A store
    outage leaves recognition to expire on its own, which grants no access.
    """
    from myf.security import sign_in_throttle as throttle

    try:
        r = get_valkey()
        throttle.revoke_account_devices(r, user_id)
        if key is not None:
            throttle.clear_throttle(r, key)
    except Exception:
        pass
