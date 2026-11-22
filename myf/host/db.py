"""The application's db module, as bound with myf.host.bind."""

from typing import Any

from myf.host import module


def __getattr__(name: str) -> Any:
    if name.startswith("__"):
        raise AttributeError(name)
    return getattr(module("db"), name)
