"""Delivering a transactional e-mail outbox.

Senders queue a row inside the transaction of the change it reports; the
worker sends waiting rows here. Every outbox (MOSP's security notices and
each application's own) is a table with the same columns: ``recipient``,
``subject``, ``body``, ``status`` (pending, sent or failed), ``attempts``,
``last_error``, ``next_attempt_at``, ``sent_at`` and ``created_at``.

- Waiting messages go oldest first, each recipient in turn: one recipient's
  backlog, however long, takes one place in each turn, so a message for
  anyone else, such as a verification link that expires or a security alert,
  is sent in the run that finds it and never waits behind the backlog.
- A failed attempt is retried with exponential backoff, and a message that
  fails MAX_ATTEMPTS times is given up. Only the error's class is recorded,
  since its text can carry SMTP credentials or addresses.
- A sent message's body is cleared, and so is the body of one given up:
  nothing will send it, and a link in it is a one-time secret.
- The worker's time limit is no failed attempt: the run stops, and the
  message waits, unchanged, for the next run.
- Sent and failed rows are deleted RETENTION after they were queued.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from mosp.core.datetime_utils import utc_now_naive as now
from mosp.core.task_deadline import TIME_LIMITS

log = logging.getLogger(__name__)

MAX_ATTEMPTS = 8
RETENTION = timedelta(days=30)


def _next_pending(db, model, served):
    return (
        db.query(model)
        .filter(
            model.status == "pending",
            model.next_attempt_at <= now(),
            model.recipient.notin_(served),
        )
        .order_by(model.created_at)
        .with_for_update(skip_locked=True)
        .first()
    )


def deliver(model, *, limit, sessions, send, label="Message"):
    """Send up to ``limit`` waiting rows of ``model``; return how many were sent.

    ``sessions`` opens a database session and ``send`` sends one message
    (``send_email``'s keywords); the caller checks that mail is configured.
    """
    sent = 0
    served: list[str] = []
    for _ in range(limit):
        with sessions() as db:
            row = _next_pending(db, model, served)
            if row is None and served:
                # Everyone waiting has had a turn; start the next one.
                served.clear()
                row = _next_pending(db, model, served)
            if row is None:
                break
            served.append(row.recipient)
            row.attempts += 1
            try:
                send(to_email=row.recipient, subject=row.subject, body=row.body)
            except TIME_LIMITS:
                raise
            except Exception as error:
                row.last_error = type(error).__name__[:100]
                row.status = "failed" if row.attempts >= MAX_ATTEMPTS else "pending"
                if row.status == "failed":
                    row.body = ""
                row.next_attempt_at = now() + timedelta(
                    seconds=min(3600, 60 * 2 ** (row.attempts - 1))
                )
                log.warning(
                    "%s %s delivery failed; attempt=%s status=%s",
                    label,
                    row.id,
                    row.attempts,
                    row.status,
                )
            else:
                row.status = "sent"
                row.sent_at = now()
                row.last_error = None
                row.body = ""
                sent += 1
            db.commit()
    with sessions() as db:
        db.query(model).filter(
            model.status.in_(["sent", "failed"]),
            model.created_at < now() - RETENTION,
        ).delete(synchronize_session=False)
        db.commit()
    return sent
