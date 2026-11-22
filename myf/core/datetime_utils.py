"""UTC values for the application's existing timestamp-without-time-zone columns.

Obtain an aware UTC value first, then deliberately remove tzinfo at the existing
naive-UTC storage boundary. This preserves comparisons, defaults and API output;
it is not a database timezone conversion. Use aware datetimes for APIs that
explicitly require them.
"""

from calendar import monthrange
from datetime import date, datetime, timedelta, timezone


def utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def to_utc_naive(value: datetime) -> datetime:
    """Convert an aware time to naive UTC; a naive time is already naive UTC."""
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def parse_iso_datetime(value: str, *, require_timezone: bool = False) -> datetime:
    """An ISO 8601 date and time as naive UTC.

    ``Z`` and offsets convert to UTC; a time without an offset is already UTC
    unless ``require_timezone`` refuses it. Fractional seconds beyond six
    digits are truncated. Anything else, a time out of range included, raises
    ``ValueError``.
    """
    try:
        parsed = datetime.fromisoformat(str(value).strip())
        if parsed.tzinfo is None:
            if require_timezone:
                raise ValueError("The time must include a timezone")
            return parsed
        return to_utc_naive(parsed)
    except OverflowError:
        raise ValueError("The time is out of range") from None


def parse_iso_datetime_or_none(value: object) -> datetime | None:
    """``parse_iso_datetime`` for best-effort readers: text it cannot read, and
    anything that is not text, is None."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return parse_iso_datetime(value)
    except ValueError:
        return None


def utc_from_timestamp_naive(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, timezone.utc).replace(tzinfo=None)


def after_inclusive_date(day: date) -> datetime:
    """The exclusive naive-UTC bound for a window that includes ``day``."""
    if day >= date.max:
        return datetime.max
    return datetime.combine(day + timedelta(days=1), datetime.min.time())


def add_months(d: date, months: int) -> date:
    """Move ``d`` by whole months, clamping the day to the target month's end."""
    month_idx = (d.month - 1) + months
    year = d.year + month_idx // 12
    month = month_idx % 12 + 1
    day = min(d.day, monthrange(year, month)[1])
    return date(year, month, day)


def iso_or_none(value: date | datetime | None) -> str | None:
    """A date or time as the API serialises it; nothing for a missing one."""
    return value.isoformat() if value else None


def iso_utc(value: datetime | None) -> str | None:
    """A naive UTC time with the Z a browser needs to read it as UTC."""
    return value.isoformat() + "Z" if value is not None else None
