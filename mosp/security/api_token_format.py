"""The form of mosp's API tokens (``mosp.security.api_tokens``).

Kept apart from the token checks, which need the application's settings,
models and store, so that redaction, which finds tokens in text, imports
nothing beyond the application's name.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from functools import lru_cache

from mosp import host
from mosp.security.regex import scan_pattern

_SECRET_BYTES = 32
SECRET_LENGTH = 43  # secrets.token_urlsafe(32)


def prefix() -> str:
    """What every token the application issues begins with."""
    return f"{host.name()}_at_"


@lru_cache(maxsize=8)
def _pattern(name: str) -> re.Pattern[str]:
    return scan_pattern(
        re.escape(f"{name}_at_") + "[A-Za-z0-9_-]{" + str(SECRET_LENGTH) + "}"
    )


def pattern() -> re.Pattern[str]:
    """The application's tokens, as redaction finds them in text."""
    return _pattern(host.name())


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def issue() -> tuple[str, str]:
    """A new token and the digest kept for it."""
    value = prefix() + secrets.token_urlsafe(_SECRET_BYTES)
    return value, digest(value)
