"""The application mosp serves.

mosp's modules reach the application's own settings, models, database sessions
and hooks through the modules in this package. An application binds them once,
before anything imports mosp's other modules, normally from its package's
``__init__``::

    import mosp.host

    mosp.host.bind(
        name="keen",
        title="Keen",
        config="app.core.config",
        models="app.db.models",
        db="app.db.session",
        hooks="app.mosp_hooks",
    )

Each role names a module path; it is imported on first use, so binding never
imports the application early. ``name`` prefixes the application's store keys,
cookie names and environment variables; ``title`` is its name in messages.
"""

from __future__ import annotations

from importlib import import_module
from types import ModuleType

ROLES = ("config", "models", "db", "hooks")
_bound: dict[str, str] = {}
_identity: dict[str, str] = {}


def bind(*, name: str, title: str, **modules: str) -> None:
    """Name the application and the module that plays each role."""
    for key, value in (("name", name), ("title", title)):
        if _identity.get(key, value) != value:
            raise RuntimeError(f"mosp's application {key} is already {_identity[key]!r}")
    if not name.isidentifier() or name != name.lower():
        raise ValueError("An application name is a lower-case identifier")
    _identity.update(name=name, title=title)
    unknown = set(modules) - set(ROLES)
    if unknown:
        raise ValueError(f"Unknown mosp host roles: {', '.join(sorted(unknown))}")
    for role, path in modules.items():
        if _bound.get(role, path) != path:
            raise RuntimeError(
                f"mosp's {role} module is already bound to {_bound[role]}"
            )
        _bound[role] = path


def module(role: str) -> ModuleType:
    """The application's module for ``role``."""
    try:
        path = _bound[role]
    except KeyError:
        raise RuntimeError(
            f"No application is bound to mosp's {role!r} role; call mosp.host.bind() "
            "before importing mosp's modules"
        ) from None
    return import_module(path)


def _identity_part(key: str) -> str:
    try:
        return _identity[key]
    except KeyError:
        raise RuntimeError(
            "No application is bound to mosp; call mosp.host.bind() before importing "
            "mosp's modules"
        ) from None


def name() -> str:
    """The application's key: the prefix of its store keys and cookie names."""
    return _identity_part("name")


def title() -> str:
    """The application's name as messages show it."""
    return _identity_part("title")


def env(setting: str) -> str:
    """The environment variable that sets ``setting``, e.g. ``KEEN_SMTP_HOST``."""
    return f"{name().upper()}_{setting.upper()}"
