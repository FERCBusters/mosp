"""Hooks the tests switch on by setting the attributes below."""

from myf.security.regex import scan_pattern

OVERRIDES: dict = {}


def __getattr__(name):
    try:
        return OVERRIDES[name]
    except KeyError:
        raise AttributeError(name) from None


ISSUED = scan_pattern(r"tst_[A-Za-z0-9]{8}")
