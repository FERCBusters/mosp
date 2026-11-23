"""How usernames compare.

Kept apart from the modules that need a bound application, because the
account models compute each account's ``login_key`` with them.
"""

from __future__ import annotations

import unicodedata

from mosp.security.encoding import digest

__all__ = ["login_key", "login_name", "printable_name"]

# Unicode Default_Ignorable_Code_Point ranges, plus the object replacement
# character that RFC 4518 also maps to nothing. Directories ignore these when
# they compare names, so they never distinguish one username from another.
_IGNORABLE = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0xFFFC, 0xFFFC),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)


def _ignorable(character: str) -> bool:
    point = ord(character)
    if unicodedata.category(character) == "Cc" and not character.isspace():
        return True
    return any(low <= point <= high for low, high in _IGNORABLE)


# Line breaks and control or format characters (bidirectional overrides among
# them) make one name look like another, so no account name holds them.
_UNPRINTED = frozenset({"Cc", "Cf", "Zl", "Zp"})


def printable_name(username: str) -> bool:
    """Whether a username holds no control, format or line-break character."""
    return not any(unicodedata.category(c) in _UNPRINTED for c in username)


def login_name(username: str) -> str:
    """The form in which sign-in names are compared for rate limiting.

    Directories match names regardless of width, case, invisible characters and
    runs of spaces (Active Directory folds fullwidth forms; RFC 4518 drops
    ignorable characters and collapses spaces), so every such variant of a
    name has one form. An empty form means the username is effectively blank.
    """
    folded = unicodedata.normalize(
        "NFKC", unicodedata.normalize("NFKC", username).casefold()
    )
    visible = "".join(c for c in folded if not _ignorable(c))
    return " ".join(visible.split())


def login_key(username: str) -> str:
    """A fixed-size digest of the compared name, kept with each account so the
    accounts a name compares equal to are found by an indexed read.

    NFKC can lengthen a name many times over, so the digest, not the compared
    name, is what is stored and indexed.
    """
    return digest(login_name(username))
