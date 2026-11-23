"""The application's db module, as bound with mosp.host.bind."""

from typing import Any

from mosp.host import module


def __getattr__(name: str) -> Any:
    if name.startswith("__"):
        raise AttributeError(name)
    return getattr(module("db"), name)
