"""What every application's Celery worker does around each task.

``connect(celery_app, sql_trace=...)`` records each task's deadline as it
starts (mosp.core.task_deadline), so a handler that swallows the worker's one
raise of the soft limit cannot keep the task going, and, with ``sql_trace``
on, labels the task's SQL statements and writes one record for it
(mosp.db.sql_trace).
"""

from __future__ import annotations

import time
from typing import Any

from celery.signals import task_postrun, task_prerun

from mosp.core import task_deadline
from mosp.db import sql_trace

# The Celery application whose default soft limit applies (set by connect).
_app: Any = None
_running: dict[str, tuple] = {}


def soft_time_limit(task) -> float | None:
    """The soft limit the worker applies to this run of ``task``."""
    _, soft = task.request.timelimit or (None, None)
    return soft or task.soft_time_limit or _app.conf.task_soft_time_limit


def start_deadline(task=None, **_):
    task_deadline.start(soft_time_limit(task))


def finish_deadline(**_):
    task_deadline.finish()


def _task_started(task_id=None, task=None, **_):
    record = {
        "kind": "task",
        "id": sql_trace.new_id(),
        "name": sql_trace.clean(task.name, 120),
    }
    token = sql_trace.begin("task", record["id"], record["name"])
    _running[task_id] = (token, time.perf_counter(), record)


def _task_finished(task_id=None, state=None, **_):
    started = _running.pop(task_id, None)
    if started is None:
        return
    token, began, record = started
    record["ms"] = round((time.perf_counter() - began) * 1000, 1)
    record["state"] = sql_trace.clean(state or "", 20)
    sql_trace.end(token, record)


def connect_task_labels() -> None:
    task_prerun.connect(_task_started, weak=False)
    task_postrun.connect(_task_finished, weak=False)


def disconnect_task_labels() -> None:
    task_prerun.disconnect(_task_started)
    task_postrun.disconnect(_task_finished)


def connect(celery_app, *, sql_trace: bool = False) -> None:
    """Wire ``celery_app``'s tasks to their deadlines, and to statement labels
    when ``sql_trace`` is on."""
    global _app
    _app = celery_app
    task_prerun.connect(start_deadline, weak=False)
    task_postrun.connect(finish_deadline, weak=False)
    if sql_trace:
        connect_task_labels()
