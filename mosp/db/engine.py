"""The application's database engine.

Every statement the engine runs checks the worker task's deadline first
(mosp.core.task_deadline), so a task past its soft time limit runs no further
statement. With ``sql_trace`` on, each statement carries the label of the
request or task that ran it (mosp.db.sql_trace).
"""

from sqlalchemy import Engine, create_engine, event

from mosp.core import task_deadline
from mosp.db.sql_trace import install_statement_labels


def within_task_deadline(conn, cursor, statement, parameters, context, executemany):
    """Refuse a statement once the worker task's deadline has passed.

    No handler can then carry the task's work on, or write the limit down as a
    failure. Undoing a savepoint is no further work: it is how the limit's own
    raise leaves a nested block, and refusing it would raise again mid-rollback.
    """
    if statement.startswith("ROLLBACK TO SAVEPOINT"):
        return
    task_deadline.check()


def application_engine(url: str, *, sql_trace: bool = False, **options) -> Engine:
    """An engine for ``url`` whose statements respect the task deadline."""
    engine = create_engine(url, pool_pre_ping=True, hide_parameters=True, **options)
    if sql_trace:
        install_statement_labels(engine)
    event.listen(engine, "before_cursor_execute", within_task_deadline)
    return engine
