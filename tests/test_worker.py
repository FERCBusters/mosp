"""The worker's wiring around each task, and audit-trail retention."""

from datetime import timedelta
from types import SimpleNamespace

import pytest
from celery import Celery
from celery.signals import task_postrun, task_prerun
from sqlalchemy.orm import sessionmaker

from mosp import worker
from mosp.core import task_deadline
from mosp.core.datetime_utils import utc_now_naive
from mosp.services import audit_retention
from tests.testapp.config import settings
from tests.testapp.models import AuditLog


@pytest.fixture
def app():
    celery_app = Celery("testapp")
    celery_app.conf.task_soft_time_limit = 3300
    yield celery_app
    task_prerun.disconnect(worker.start_deadline)
    task_postrun.disconnect(worker.finish_deadline)
    worker.disconnect_task_labels()
    task_deadline.finish()


class _Task:
    """A task as the worker's signals carry it (hashable, as senders are)."""

    def __init__(self, limits, annotated, name):
        self.name = name
        self.request = SimpleNamespace(timelimit=limits)
        self.soft_time_limit = annotated


def _task(limits=None, annotated=None, name="testapp.synthetic"):
    return _Task(limits, annotated, name)


def test_each_task_records_its_soft_limit_as_it_starts(app, monkeypatch):
    worker.connect(app)
    started = []
    monkeypatch.setattr(task_deadline, "start", started.append)
    for limits, annotated in (((600, 480), None), (None, 1500), (None, None)):
        task = _task(limits, annotated)
        task_prerun.send(sender=task, task_id="t", task=task)
    assert started == [480, 1500, 3300]
    assert worker.soft_time_limit(_task((None, None))) == 3300

    task_deadline.start(0.5)
    task_postrun.send(sender=None, task_id="t", task=None, state="SUCCESS")
    task_deadline.check()


def test_tasks_are_labelled_only_with_tracing_on(app, capsys):
    worker.connect(app)
    task = _task(name="testapp.untraced")
    task_prerun.send(sender=task, task_id="quiet", task=task)
    assert worker._running == {}
    task_postrun.send(sender=task, task_id="quiet", task=task, state="SUCCESS")

    worker.connect(app, sql_trace=True)
    # A task that finishes without having started here leaves no record.
    task_postrun.send(sender=task, task_id="elsewhere", task=task, state="SUCCESS")
    task = _task(name="testapp.traced")
    task_prerun.send(sender=task, task_id="loud", task=task)
    assert "loud" in worker._running
    task_postrun.send(sender=task, task_id="loud", task=task, state="SUCCESS")
    assert worker._running == {}

    lines = [line for line in capsys.readouterr().err.splitlines() if line]
    assert len(lines) == 1
    assert lines[0].startswith("TESTAPP_SQL_TRACE ")
    assert '"name": "testapp.traced"' in lines[0]
    assert '"state": "SUCCESS"' in lines[0]


# -- audit-trail retention ----------------------------------------------------


def test_expired_records_are_deleted_oldest_first_in_short_batches(db, monkeypatch):
    # Each batch commits in its own session, as the worker's would.
    monkeypatch.setattr(
        audit_retention,
        "SessionLocal",
        sessionmaker(
            bind=db.get_bind(),
            autoflush=False,
            join_transaction_mode="create_savepoint",
        ),
    )
    monkeypatch.setattr(audit_retention, "BATCH_SIZE", 2)
    monkeypatch.setattr(audit_retention, "BATCHES_PER_RUN", 2)
    monkeypatch.setattr(settings, "audit_log_retention_days", 400)
    now = utc_now_naive()
    for days in (900, 700, 600, 500, 401, 399, 1, 0):
        db.add(
            AuditLog(
                ts=now - timedelta(days=days, minutes=1),
                method="GET",
                path=f"/v1/aged/{days}",
                status_code=200,
                duration_ms=1,
            )
        )
    db.commit()

    def kept():
        db.expire_all()
        return sorted(
            int(path.rsplit("/", 1)[1]) for (path,) in db.query(AuditLog.path)
        )

    # A run stops after its batches and says more remain.
    assert audit_retention.remove_expired(now) == (4, True)
    assert kept() == [0, 1, 399, 401]
    assert audit_retention.remove_expired(now) == (1, False)
    assert kept() == [0, 1, 399]

    # 0 keeps every record.
    monkeypatch.setattr(settings, "audit_log_retention_days", 0)
    assert audit_retention.remove_expired(now + timedelta(days=10_000)) == (0, False)
    assert kept() == [0, 1, 399]


def test_expired_sign_in_rows_are_removed_and_current_ones_kept(db, monkeypatch):
    from mosp.services import housekeeping
    from tests.testapp.models import (
        MfaChallenge,
        OidcLoginState,
        SsoEmailChallenge,
        User,
    )

    monkeypatch.setattr(
        housekeeping,
        "SessionLocal",
        sessionmaker(bind=db.get_bind(), join_transaction_mode="create_savepoint"),
    )
    now = utc_now_naive()
    user = User(username="kept", password_hash="x", role="normal")
    db.add(user)
    db.flush()
    for expires in (now - timedelta(seconds=1), now + timedelta(minutes=5)):
        db.add(_row(OidcLoginState, expires))
        db.add(_row(MfaChallenge, expires, user_id=user.id))
        db.add(_row(SsoEmailChallenge, expires, user_id=user.id))
    db.commit()

    assert housekeeping.remove_expired(now) == {
        "oidc_login_states": 1,
        "mfa_challenges": 1,
        "sso_email_challenges": 1,
    }
    db.expire_all()
    for model in (OidcLoginState, MfaChallenge, SsoEmailChallenge):
        assert db.query(model).count() == 1


def _row(model, expires, **fields):
    import secrets

    token = secrets.token_hex(8)
    values = {
        "OidcLoginState": dict(state=token, nonce=token, code_verifier=token),
        "MfaChallenge": dict(
            token_hash=token,
            purpose="sign-in",
            stage="verify",
            version=0,
            password_digest=token,
        ),
        "SsoEmailChallenge": dict(
            token_hash=token,
            email=f"{token}@example.org",
            mfa_version=0,
            password_digest=token,
        ),
    }[model.__name__]
    return model(expires_at=expires, **values, **fields)
