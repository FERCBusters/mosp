"""Identifiers as routes and requests spell them."""

from __future__ import annotations

import uuid
from typing import Optional


def try_uuid(v: object) -> Optional[uuid.UUID]:
    """The UUID ``v`` names, written as 36 characters or as 32 hexadecimal digits.

    Python also reads braces, a URN prefix and any number of hyphens anywhere.
    Those spellings are refused, so a record has one identifier in a route's
    path and no padding can lengthen a path that still reaches it.
    """
    text = str(v)
    try:
        parsed = uuid.UUID(text)
    except ValueError:
        return None
    return parsed if text.lower() in (str(parsed), parsed.hex) else None
