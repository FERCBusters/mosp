"""Dates and times as the application stores them, a worker task's deadline,
and how one input's failure is described."""

import socket
import ssl
import time
from datetime import date, datetime, timedelta, timezone

import httpx2 as httpx
import pytest
from celery.exceptions import SoftTimeLimitExceeded, TimeLimitExceeded

from mosp.core import datetime_utils as dt
from mosp.core import task_deadline
from mosp.security.errors import collection_error

# -- dates and times ----------------------------------------------------------


def test_times_are_stored_as_naive_utc():
    naive = datetime(2026, 1, 2, 3, 4)
    assert dt.to_utc_naive(naive) is naive
    aware = datetime(2026, 1, 2, 13, 4, tzinfo=timezone(timedelta(hours=10)))
    assert dt.to_utc_naive(aware) == naive


def test_iso_times_are_read_as_naive_utc():
    assert dt.parse_iso_datetime(" 2026-01-02T03:04:05Z ") == datetime(
        2026, 1, 2, 3, 4, 5
    )
    assert dt.parse_iso_datetime("2026-01-02T03:04:05") == datetime(2026, 1, 2, 3, 4, 5)
    with pytest.raises(ValueError, match="must include a timezone"):
        dt.parse_iso_datetime("2026-01-02T03:04:05", require_timezone=True)
    with pytest.raises(ValueError, match="out of range"):
        dt.parse_iso_datetime("0001-01-01T00:00:00+01:00")
    assert dt.parse_iso_datetime_or_none("2026-01-02") == datetime(2026, 1, 2)
    for unreadable in (None, 5, "", " ", "yesterday"):
        assert dt.parse_iso_datetime_or_none(unreadable) is None


def test_a_window_including_a_day_ends_at_the_next_midnight():
    assert dt.after_inclusive_date(date(2026, 2, 28)) == datetime(2026, 3, 1)
    assert dt.after_inclusive_date(date.max) == datetime.max


@pytest.mark.parametrize(
    "start,months,moved",
    [
        (date(2026, 1, 31), 1, date(2026, 2, 28)),
        (date(2024, 1, 31), 1, date(2024, 2, 29)),
        (date(2026, 11, 15), 3, date(2027, 2, 15)),
        (date(2026, 3, 31), -1, date(2026, 2, 28)),
        (date(2026, 1, 15), -13, date(2024, 12, 15)),
    ],
)
def test_months_move_by_calendar_months_clamped_to_the_month_end(start, months, moved):
    assert dt.add_months(start, months) == moved


def test_times_are_serialised_as_the_api_writes_them():
    assert dt.iso_or_none(date(2026, 1, 2)) == "2026-01-02"
    assert dt.iso_or_none(None) is None
    assert dt.iso_utc(datetime(2026, 1, 2, 3, 4)) == "2026-01-02T03:04:00Z"
    assert dt.iso_utc(None) is None


# -- a worker task's deadline -------------------------------------------------


@pytest.fixture
def task():
    yield task_deadline
    task_deadline.finish()


def test_outside_a_task_a_check_does_nothing(task):
    task.start(None)
    assert not task.passed()
    task.check()


def test_the_deadline_falls_ahead_of_the_soft_limit(task, monkeypatch):
    now = [100.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    task.start(10)
    now[0] = 108.9
    task.check()
    now[0] = 109.0
    assert task.passed()
    with pytest.raises(SoftTimeLimitExceeded):
        task.check()
    # Tidying up after the limit runs past it.
    with task.grace():
        task.check()
    with pytest.raises(SoftTimeLimitExceeded):
        task.check()
    task.finish()
    task.check()


def test_a_limit_shorter_than_the_lead_has_already_passed(task):
    task.start(0.5)
    with pytest.raises(SoftTimeLimitExceeded):
        task.check()


# -- one input's failure ------------------------------------------------------


def _status_error(status):
    request = httpx.Request("GET", "https://upstream.example/secret?token=x")
    response = httpx.Response(status, request=request, text="secret body")
    return httpx.HTTPStatusError("failed", request=request, response=response)


@pytest.mark.parametrize(
    "error,description",
    [
        (_status_error(502), "Collection failed: upstream returned HTTP 502"),
        (TimeoutError(), "Collection timed out; narrow the input"),
        (httpx.ReadTimeout("slow"), "Collection timed out; narrow the input"),
        (ssl.SSLError("bad cert"), "TLS verification failed"),
        (socket.gaierror("no such host"), "Connection failed; check DNS"),
        (httpx.ConnectError("refused"), "Connection failed; check DNS"),
        (RuntimeError("password=hunter2"), "Collection failed; check the input"),
    ],
)
def test_a_failure_is_described_without_what_it_carried(error, description):
    described = collection_error(error)
    assert described.startswith(description)
    assert "secret" not in described and "hunter2" not in described


@pytest.mark.parametrize("limit", [SoftTimeLimitExceeded(), TimeLimitExceeded()])
def test_the_time_limit_is_not_one_inputs_failure(limit):
    with pytest.raises(type(limit)):
        collection_error(limit)


def test_a_deadline_that_passed_during_the_failure_ends_the_run(task):
    task.start(0.5)
    with pytest.raises(SoftTimeLimitExceeded):
        collection_error(RuntimeError("input failed"))


# -- the application engine ---------------------------------------------------


def test_the_engine_runs_no_statement_past_the_deadline(task):
    from sqlalchemy import text

    from mosp.db.engine import application_engine
    from tests.testapp.config import settings

    engine = application_engine(settings.database_url)
    try:
        with engine.connect() as connection:
            assert connection.execute(text("SELECT 1")).scalar() == 1
            savepoint = connection.begin_nested()
            task.start(0.5)
            with pytest.raises(SoftTimeLimitExceeded):
                connection.execute(text("SELECT 1"))
            # Leaving the savepoint the limit interrupted is no further work.
            savepoint.rollback()
            with task.grace():
                assert connection.execute(text("SELECT 2")).scalar() == 2
    finally:
        engine.dispose()


def test_the_engine_labels_statements_only_when_tracing(task):
    from sqlalchemy import event, text

    from mosp.db import sql_trace
    from mosp.db.engine import application_engine
    from tests.testapp.config import settings

    for tracing, labelled in ((False, False), (True, True)):
        engine = application_engine(settings.database_url, sql_trace=tracing)
        seen = []
        event.listen(
            engine,
            "after_cursor_execute",
            lambda conn, cursor, statement, *args: seen.append(statement),
        )
        try:
            token = sql_trace.begin("task", "0123456789ab", "test")
            try:
                with engine.connect() as connection:
                    connection.execute(text("SELECT 1"))
            finally:
                sql_trace.end(token, {})
        finally:
            engine.dispose()
        assert seen[-1].startswith("/* testapp task=0123456789ab") is labelled
