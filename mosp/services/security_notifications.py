"""Transactional security-email outbox and per-user successful-login IP history."""

from sqlalchemy.dialects.postgresql import insert

from mosp import host
from mosp.core.datetime_utils import utc_now_naive as now
from mosp.core.email_address import single_mailbox
from mosp.host import hooks
from mosp.host.config import settings
from mosp.host.db import SessionLocal
from mosp.host.models import SecurityNotification, UserLoginIP
from mosp.security.mfa import CODE_ATTEMPTS
from mosp.services import outbox
from mosp.services.mailer import send_email, smtp_configured


def enqueue(db, user, event, *, ip=None, detail=None):
    """Queue the account holder's notice of ``event``; ``detail`` names what it
    concerns, such as the sign-in identity a link added."""
    recipient = single_mailbox(user.email)
    if not smtp_configured() or not recipient:
        return
    address = ip or "Unavailable (operator action or unknown address)"
    app = host.title()
    titles = {
        "sso-email-added": f"An SSO email address was verified for your {app} account",
        "sso-email-removed": f"An SSO email address was removed from your {app} account",
        "sso-identity-linked": f"A sign-in identity was linked to your {app} account",
        "sso-identity-removed": f"A sign-in identity was removed from your {app} account",
        "login-ip": "Sign-in from an unfamiliar IP address",
        "password-changed": f"Your {app} password was changed",
        "password-reset": f"Your {app} password was reset by an administrator",
        "factor-enrolled": f"An authenticator was added to your {app} account",
        "factor-removed": f"An authenticator was removed from your {app} account",
        "recovery-codes-regenerated": f"Your {app} recovery codes were replaced",
        "operator-reset": f"Your {app} two-factor authentication was reset by an operator",
        "verified-recovery": f"A recovery code was used for your {app} account",
        "verification-ended": f"{app} ended a two-factor verification after repeated incorrect codes",
    }
    # The application's own notices: a title and the paragraph explaining it.
    own = hooks.security_notice(event)
    title = own[0] if own else titles[event]
    body = f"{title}.\n\nAccount: {user.username}\n{app} installation: {settings.public_base_url}\nTime (UTC): {now().isoformat(timespec='seconds')}Z\nIP address: {address}\n\n"
    if detail:
        body += detail + "\n\n"
    if own:
        body += own[1] + "\n\n"
    elif event == "login-ip":
        body += "This address has not previously been recorded for a successful sign-in to this account. A VPN, mobile connection or changing ISP address can cause this alert.\n\n"
    elif event == "verification-ended":
        body += f"Your password was accepted and {CODE_ATTEMPTS} incorrect authenticator or recovery codes were entered within an hour, so {app} accepts no code for this account for the next hour; a security key still signs you in. If this was not you, someone may know your password: change it and contact your {app} administrator.\n\n"
    elif event == "sso-identity-linked":
        body += f"This identity can now sign in to your account without your {app} password or authenticator. If you do not recognise it, remove it from your account's linked sign-in identities, which also removes the address it was linked through, or ask your {app} administrator to reset your account.\n\n"
    elif event == "sso-identity-removed":
        body += "Every session of your account has ended. Remove any address or identity above that you do not recognise.\n\n"
    elif event == "verified-recovery":
        body += "Each recovery code works once. Replace your recovery codes under Account, Security when few remain.\n\n"
    body += f"If this was you, no action is needed. If you do not recognise this activity, open your known {app} address directly and contact your {app} administrator. Review your password and authenticators.\n"
    queue_email(
        db,
        user_id=user.id,
        recipient=recipient,
        subject=f"{app} security: " + title,
        body=body,
    )


def queue_email(db, *, user_id, recipient, subject, body):
    """Queue an email in the caller's transaction; the worker sends it with retries."""
    db.add(
        SecurityNotification(
            user_id=user_id, recipient=recipient, subject=subject, body=body
        )
    )


def record_login(db, user, *, ip):
    address = ip
    if not address:
        return
    # Unique account/IP key makes parallel sign-ins enqueue only one alert.
    created = db.execute(
        insert(UserLoginIP)
        .values(user_id=user.id, address=address, first_seen_at=now())
        .on_conflict_do_nothing()
        .returning(UserLoginIP.address)
    ).scalar_one_or_none()
    if created:
        enqueue(db, user, "login-ip", ip=address)


def pending_for(db, user_id) -> int:
    """How many messages are waiting to be sent to an account."""
    return (
        db.query(SecurityNotification)
        .filter_by(user_id=user_id, status="pending")
        .count()
    )


def deliver_pending(limit=10):
    """Send waiting security notices (mosp.services.outbox)."""
    if not smtp_configured():
        return 0
    return outbox.deliver(
        SecurityNotification,
        limit=limit,
        sessions=SessionLocal,
        send=send_email,
        label="Security notification",
    )
