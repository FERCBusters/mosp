#!/usr/bin/env python3
"""Find the parts of myf that no application built on it uses.

Usage: unused_by_apps.py [--myf DIR] [--tests DIR] [--coverage FILE ...]
                         [NAME=]APP_SOURCE [[NAME=]APP_SOURCE ...]

myf is reached only through the applications built on it, so code none of
them can reach is dead even when myf's own tests exercise it. Each
APP_SOURCE is a source tree of an application (KEEN's services/api/app, its
scripts and its migrations, say); trees given the same NAME are one
application. An application's tests are better left out: what only they use
is not used.

Two signals, each narrowing the other:

- Reachability. Every module-level function, class and constant in myf is a
  node. A node's edges are the myf names its body refers to, through any
  import or module alias, re-exports followed to the definition. The roots are
  every myf name the applications refer to, and the module-level code of every
  module that is reached, since importing a module runs it. A function
  registered by a decorator (a route on a router, an event listener) is
  reached once what it is registered with is. A class is one node: its
  methods are reached with it. What the roots never reach is unused.
- Execution. Given coverage data files from the applications' test suites,
  run with ``--cov=myf`` against the same myf checkout, a reachable function
  that none of them ran is listed too: reachable in principle, never run by
  any application's tests.

Each unused name says whether myf's own tests (``--tests``) refer to it, so a
name kept alive only by its tests stands out. With more than one
application, the names only one of them reaches are listed under it: shared
code one application alone uses may belong in that application. Nothing is changed: the report
is a list of candidates to read, not to delete blindly. Names myf calls by
string (the application's hooks, settings and models) belong to the
applications and are not myf's nodes.
"""

from __future__ import annotations

import argparse
import ast
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

PACKAGE = "myf"


@dataclass
class Module:
    name: str
    path: Path
    tree: ast.Module
    # Local name -> what it names: ("module", dotted) or ("symbol", node id).
    names: dict[str, tuple[str, str]] = field(default_factory=dict)
    defined: dict[str, ast.AST] = field(default_factory=dict)


def _module_name(root: Path, path: Path) -> str:
    parts = list(path.relative_to(root.parent).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _absolute(module: str, is_package: bool, node: ast.ImportFrom) -> str:
    if not node.level:
        return node.module or ""
    base = module.split(".")
    if not is_package:
        base = base[:-1]
    base = base[: len(base) - (node.level - 1)]
    return ".".join(base + ([node.module] if node.module else []))


class Index:
    """myf's modules and their top-level definitions."""

    def __init__(self, root: Path):
        self.root = root
        self.modules: dict[str, Module] = {}
        for path in sorted(root.rglob("*.py")):
            name = _module_name(root, path)
            tree = ast.parse(path.read_text(), str(path))
            module = Module(name, path, tree)
            for node in tree.body:
                for defined in _definitions(node):
                    module.defined[defined] = node
            self.modules[name] = module
        for module in self.modules.values():
            module.names = self.import_names(module.name, module.path, module.tree)
            for defined in module.defined:
                module.names.setdefault(defined, ("symbol", f"{module.name}:{defined}"))

    def resolve(self, module: str, name: str, seen=None) -> tuple[str, str] | None:
        """What ``name`` in myf module ``module`` names, re-exports followed."""
        if f"{module}.{name}" in self.modules:
            return ("module", f"{module}.{name}")
        target = self.modules.get(module)
        if target is None:
            return None
        if name in target.defined:
            return ("symbol", f"{module}:{name}")
        seen = seen or set()
        if (module, name) in seen:
            return None
        seen.add((module, name))
        imported = self.import_names(module, target.path, target.tree, only=name)
        found = imported.get(name)
        if found and found[0] == "reexport":
            source, original = found[1].split(":", 1)
            return self.resolve(source, original, seen)
        return found

    def import_names(self, module, path, tree, only=None):
        """The myf modules and names a file imports, under their local names.

        Imports anywhere in the file count, function bodies included: myf
        imports some names where they are used, to avoid import cycles.
        """
        is_package = path.name == "__init__.py"
        names: dict[str, tuple[str, str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] != PACKAGE:
                        continue
                    if alias.asname:
                        names[alias.asname] = ("module", alias.name)
                    else:
                        names.setdefault(PACKAGE, ("module", PACKAGE))
            elif isinstance(node, ast.ImportFrom):
                source = _absolute(module, is_package, node)
                if source.split(".")[0] != PACKAGE:
                    continue
                for alias in node.names:
                    local = alias.asname or alias.name
                    if only is not None and local != only:
                        continue
                    if alias.name == "*":
                        continue
                    if f"{source}.{alias.name}" in self.modules:
                        names[local] = ("module", f"{source}.{alias.name}")
                    elif only is not None:
                        names[local] = ("reexport", f"{source}:{alias.name}")
                    else:
                        # A name the module provides at run time (a module
                        # __getattr__) is still the module's.
                        names[local] = self.resolve(source, alias.name) or (
                            "symbol",
                            f"{source}:{alias.name}",
                        )
        return names


def _definitions(node: ast.stmt) -> list[str]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    targets: list[ast.expr] = []
    if isinstance(node, ast.Assign):
        targets = node.targets
    elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        targets = [node.target]
    out = []
    for target in targets:
        for name in ast.walk(target):
            if isinstance(name, ast.Name):
                out.append(name.id)
    return out


def _dotted(node: ast.expr) -> list[str] | None:
    """``a.b.c`` as ["a", "b", "c"], or None for anything else."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return parts[::-1]


def references(index: Index, names: dict, nodes) -> set[str]:
    """The myf node ids (``module:name``, or ``module:`` for a module's
    top-level code) the given AST nodes refer to."""
    found: set[str] = set()
    for root in nodes:
        for node in ast.walk(root):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            # Assigning a name defines it; only reading it uses it.
            if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
                continue
            chain = (
                _dotted(node) if isinstance(node, (ast.Attribute, ast.Name)) else None
            )
            if not chain or chain[0] not in names:
                continue
            kind, target = names[chain[0]]
            rest = chain[1:]
            while kind == "module":
                found.add(f"{target}:")
                if not rest:
                    break
                resolved = index.resolve(target, rest[0])
                if resolved is None:
                    break
                kind, target = resolved
                rest = rest[1:]
            if kind == "symbol":
                found.add(target)
    return found


def _decorators(node: ast.AST) -> list[ast.expr]:
    return list(getattr(node, "decorator_list", []))


def graph(index: Index):
    """Each node's references, and the nodes each decorator registers."""
    edges: dict[str, set[str]] = defaultdict(set)
    registered_by: dict[str, set[str]] = defaultdict(set)
    for module in index.modules.values():
        body_code = [
            node
            for node in module.tree.body
            if not isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            )
        ]
        edges[f"{module.name}:"] |= references(index, module.names, body_code)
        # Importing a module runs its code.
        edges[f"{module.name}:"] |= {
            f"{target}:" if kind == "module" else target.split(":")[0] + ":"
            for kind, target in module.names.values()
            if not (kind == "symbol" and target.startswith(f"{module.name}:"))
        }
        for node in module.tree.body:
            if not isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                for name in _definitions(node):
                    # A constant is reached with its module's code, and its
                    # value refers to what the module's code refers to.
                    edges[f"{module.name}:{name}"] |= references(
                        index, module.names, [node]
                    )
                    if name.startswith("__") and name.endswith("__"):
                        # Python reads __all__ and the like itself.
                        edges[f"{module.name}:"].add(f"{module.name}:{name}")
                continue
            ident = f"{module.name}:{node.name}"
            if node.name.startswith("__") and node.name.endswith("__"):
                # Python calls a module's __getattr__ and the like itself.
                edges[f"{module.name}:"].add(ident)
            edges[ident] |= references(index, module.names, [node])
            for registrar in references(index, module.names, _decorators(node)):
                registered_by[registrar].add(ident)
            # Each node is part of its module: reaching it runs the module.
            edges[ident].add(f"{module.name}:")
    return edges, registered_by


def reachable(edges, registered_by, roots: set[str]) -> set[str]:
    seen: set[str] = set()
    pending = list(roots)
    while pending:
        node = pending.pop()
        if node in seen:
            continue
        seen.add(node)
        if node.endswith(":"):
            # A package's code runs before its modules'.
            package = node[:-1].rsplit(".", 1)[0]
            if "." in node[:-1] or package != node[:-1]:
                pending.append(f"{package}:")
        pending.extend(edges.get(node, ()))
        pending.extend(registered_by.get(node, ()))
    return seen


def tree_references(index: Index, sources: list[Path]) -> set[str]:
    found: set[str] = set()
    for source in sources:
        for path in sorted(source.rglob("*.py")) if source.is_dir() else [source]:
            tree = ast.parse(path.read_text(), str(path))
            names = index.import_names("__app__", path, tree)
            found |= references(index, names, [tree])
            # An application's import counts as a use: it may be there to
            # re-export the name. Importing a module runs it either way.
            found |= {target for kind, target in names.values() if kind == "symbol"}
            found |= {
                f"{target}:" for kind, target in names.values() if kind == "module"
            }
            found |= {target.split(":")[0] + ":" for kind, target in names.values()}
    return found


def _function_lines(node: ast.AST) -> set[int]:
    body = getattr(node, "body", [])
    return {
        line
        for statement in body
        for line in range(
            statement.lineno, (statement.end_lineno or statement.lineno) + 1
        )
    }


def unexecuted(index: Index, nodes: set[str], coverage_files: list[Path]) -> set[str]:
    """Of ``nodes``, the functions and classes no coverage file ran a line of."""
    from coverage import CoverageData

    executed: dict[str, set[int]] = defaultdict(set)
    for data_file in coverage_files:
        data = CoverageData(basename=str(data_file))
        data.read()
        for measured in data.measured_files():
            executed[str(Path(measured).resolve())] |= set(data.lines(measured) or ())
    out = set()
    for ident in nodes:
        module_name, name = ident.split(":", 1)
        if not name:
            continue
        module = index.modules[module_name]
        node = module.defined.get(name)
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        lines = _function_lines(node)
        if isinstance(node, ast.ClassDef):
            lines = set().union(
                *(
                    _function_lines(n)
                    for n in node.body
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                ),
                set(),
            )
            if not lines:
                continue
        if not lines & executed.get(str(module.path.resolve()), set()):
            out.add(ident)
    return out


def _attribute_names(sources: list[Path]) -> set[str]:
    """Every attribute name and string constant in the given trees: a method
    is used under any of them (``obj.name``, ``getattr(obj, "name")``)."""
    names: set[str] = set()
    for source in sources:
        for path in sorted(source.rglob("*.py")) if source.is_dir() else [source]:
            for node in ast.walk(ast.parse(path.read_text(), str(path))):
                if isinstance(node, ast.Attribute):
                    names.add(node.attr)
                elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                    names.add(node.value)
                elif isinstance(node, ast.keyword) and node.arg:
                    names.add(node.arg)
    return names


def unused_methods(index: Index, seen: set[str], sources: list[Path]) -> set[str]:
    """Methods of reached classes whose name nothing uses as an attribute.

    A name is matched wherever it is used, on any object, so a method listed
    here is unused; one with a common name may be unused but not listed. A
    method a framework calls by its own name (``__call__``, ``dispatch``) is
    not listed when the name appears in the framework's use: dunders never
    are.
    """
    used = _attribute_names([index.root, *sources])
    out = set()
    for ident in seen:
        module_name, name = ident.split(":", 1)
        node = index.modules[module_name].defined.get(name) if name else None
        if not isinstance(node, ast.ClassDef):
            continue
        for member in node.body:
            if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if member.name.startswith("__") or member.name in used:
                continue
            # A decorated method is registered with what decorates it (a
            # validator, a property), and one a base class outside myf
            # declares is called by that class.
            if member.decorator_list or _overrides(
                index, module_name, node, member.name
            ):
                continue
            out.add(f"{ident}.{member.name}")
    return out


def _overrides(index: Index, module_name: str, cls: ast.ClassDef, name: str) -> bool:
    """Whether a base class from outside myf has an attribute ``name``."""
    import importlib

    imported: dict[str, str] = {}
    for node in ast.walk(index.modules[module_name].tree):
        if isinstance(node, ast.ImportFrom) and not node.level and node.module:
            for alias in node.names:
                imported[alias.asname or alias.name] = f"{node.module}:{alias.name}"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imported[alias.asname or alias.name] = alias.name
    for base in cls.bases:
        chain = _dotted(base)
        if not chain or chain[0] not in imported:
            continue
        source = imported[chain[0]]
        try:
            if ":" in source:
                module, attribute = source.split(":")
                target = getattr(importlib.import_module(module), attribute)
            else:
                target = importlib.import_module(source)
            for part in chain[1:]:
                target = getattr(target, part)
        except (ImportError, AttributeError):
            continue
        if source.split(".")[0] != PACKAGE and hasattr(target, name):
            return True
    return False


def _hook_names(index: Index) -> set[str]:
    module = index.modules.get(f"{PACKAGE}.host.hooks")
    if module is None:
        return set()
    return {
        node.args[0].value
        for node in ast.walk(module.tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_hook"
        and node.args
        and isinstance(node.args[0], ast.Constant)
    }


def provided_hooks(sources: list[Path]) -> set[str]:
    """The hooks the applications define: the top-level names of each module
    an application names as its hooks in ``myf.host.bind(hooks=...)``."""
    # Applications may name their modules alike, so each is found under the
    # directory its source tree sits in.
    modules: set[tuple[Path, str]] = set()
    files: dict[tuple[Path, str], Path] = {}
    for source in sources:
        home = source.resolve().parent
        for path in sorted(source.rglob("*.py")) if source.is_dir() else [source]:
            tree = ast.parse(path.read_text(), str(path))
            parts = path.resolve().relative_to(home).with_suffix("").parts
            files[(home, ".".join(parts))] = path
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and (_dotted(node.func) or [""])[-1] == "bind"
                ):
                    for keyword in node.keywords:
                        if keyword.arg == "hooks" and isinstance(
                            keyword.value, ast.Constant
                        ):
                            modules.add((home, keyword.value.value))
    names: set[str] = set()
    for module in modules:
        path = files.get(module)
        if path is not None:
            for node in ast.parse(path.read_text()).body:
                names.update(_definitions(node))
    return names


def report(index, unused, tested, unrun, methods=(), hooks=None, only=None) -> str:
    lines = []
    by_module: dict[str, list[str]] = defaultdict(list)
    for ident in unused:
        module, name = ident.split(":", 1)
        by_module[module].append(name or "(the whole module)")
    lines.append(f"Unreachable from the applications: {len(unused)}")
    for module in sorted(by_module):
        lines.append(f"  {module}")
        for name in sorted(by_module[module]):
            ident = f"{module}:{name if name != '(the whole module)' else ''}"
            mark = "  (myf's tests use it)" if ident in tested else ""
            lines.append(f"    {name}{mark}")
    for app, names in sorted((only or {}).items()):
        lines.append("")
        lines.append(f"Reached only by {app}: {len(names)}")
        grouped: dict[str, list[str]] = defaultdict(list)
        for ident in names:
            module, name = ident.split(":", 1)
            grouped[module].append(name)
        for module in sorted(grouped):
            lines.append(f"  {module}: {', '.join(sorted(grouped[module]))}")
    if methods:
        lines.append("")
        lines.append(f"Methods whose name nothing uses: {len(methods)}")
        for ident in sorted(methods):
            lines.append(f"  {ident}")
    if hooks is not None:
        lines.append("")
        lines.append(
            f"Hooks no application provides (myf's default always runs): {len(hooks)}"
        )
        for name in sorted(hooks):
            lines.append(f"  {name}")
    if unrun is not None:
        lines.append("")
        lines.append(f"Reachable, but no application's tests ran it: {len(unrun)}")
        for ident in sorted(unrun):
            lines.append(f"  {ident}")
    return "\n".join(lines) + "\n"


def analyse(
    myf_dir: Path,
    apps: list[Path] | dict[str, list[Path]],
    tests: list[Path],
    coverage_files: list[Path],
):
    if not isinstance(apps, dict):
        apps = {"applications": list(apps)}
    index = Index(myf_dir)
    edges, registered_by = graph(index)
    reach = {
        name: reachable(edges, registered_by, tree_references(index, trees))
        for name, trees in apps.items()
    }
    seen = set().union(*reach.values())
    only = None
    if len(reach) > 1:
        only = {
            name: {
                ident
                for ident in reached
                if not ident.endswith(":")
                and not any(
                    ident in other for key, other in reach.items() if key != name
                )
            }
            for name, reached in reach.items()
        }
    apps = [tree for trees in apps.values() for tree in trees]
    every = {
        f"{module.name}:{name}"
        for module in index.modules.values()
        for name in module.defined
    } | {f"{name}:" for name in index.modules}
    unused = {
        ident
        for ident in every - seen
        # A module none of whose names are listed is listed whole.
        if not (
            ident.endswith(":") is False and f"{ident.split(':')[0]}:" in every - seen
        )
    }
    tested_roots = tree_references(index, tests) if tests else set()
    tested = reachable(edges, registered_by, tested_roots)
    unrun = unexecuted(index, seen, coverage_files) if coverage_files else None
    methods = unused_methods(index, seen, apps)
    hooks = _hook_names(index) - provided_hooks(apps)
    return index, unused, tested, unrun, methods, hooks, only


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("apps", nargs="+", metavar="[NAME=]APP_SOURCE")
    here = Path(__file__).resolve().parents[1]
    parser.add_argument("--myf", type=Path, default=here / PACKAGE)
    parser.add_argument("--tests", type=Path, action="append", default=[])
    parser.add_argument("--coverage", type=Path, action="append", default=[])
    args = parser.parse_args(argv)
    apps: dict[str, list[Path]] = defaultdict(list)
    for given in args.apps:
        name, _, tree = given.rpartition("=")
        apps[name or tree].append(Path(tree))
    index, unused, tested, unrun, methods, hooks, only = analyse(
        args.myf, dict(apps), args.tests, args.coverage
    )
    sys.stdout.write(report(index, unused, tested, unrun, methods, hooks, only))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
