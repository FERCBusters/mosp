"""Sign-in rows past their use: removed on the worker's schedule.

OIDC login states, second-factor challenges and SSO address proofs each
expire, and are refused once they have; removing them keeps a flood of
started sign-ins, ceremonies or proofs from growing their tables without
bound. Each kind is removed in its own short transaction.
"""

from __future__ import annotations

from datetime import datetime

from mosp.core.datetime_utils import utc_now_naive
from mosp.host.db import SessionLocal
from mosp.host.models import MfaChallenge, OidcLoginState, SsoEmailChallenge


def remove_expired(now: datetime | None = None) -> dict[str, int]:
    """Delete expired rows; return how many of each kind."""
    now = now or utc_now_naive()
    removed = {}
    for name, model in (
        ("oidc_login_states", OidcLoginState),
        ("mfa_challenges", MfaChallenge),
        ("sso_email_challenges", SsoEmailChallenge),
    ):
        with SessionLocal() as db:
            removed[name] = (
                db.query(model)
                .filter(model.expires_at <= now)
                .delete(synchronize_session=False)
            )
            db.commit()
    return removed
