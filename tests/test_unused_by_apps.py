"""tools/unused_by_apps.py: the parts of mosp no application built on it uses."""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "unused_by_apps", ROOT / "tools" / "unused_by_apps.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


tool = _load_tool()

FRAMEWORK = {
    "mosp/__init__.py": "",
    "mosp/host/__init__.py": "",
    "mosp/host/hooks.py": (
        "def _hook(name):\n"
        "    return None\n"
        "def page():\n"
        '    return _hook("pages")\n'
        "def limit():\n"
        '    return _hook("limit")\n'
    ),
    "mosp/names.py": (
        "def fold(text):\n    return text.lower()\ndef unused_helper():\n    return 1\n"
    ),
    "mosp/api.py": (
        "from html.parser import HTMLParser\n"
        "from mosp.names import fold\n"
        "from mosp.host import hooks\n"
        "router = Router()\n"
        "CONSTANT = 3\n"
        '@router.post("/x")\n'
        "def endpoint():\n"
        "    return hooks.limit()\n"
        "def helper_only_tests():\n"
        "    return 2\n"
        "class Parser(HTMLParser):\n"
        "    def handle_data(self, data):\n"
        "        pass\n"
        "    def used_method(self):\n"
        "        pass\n"
        "    def stray(self):\n"
        "        pass\n"
        "def lazy():\n"
        "    from mosp.names import fold as folded\n"
        '    return folded("A")\n'
    ),
    "mosp/dead.py": "def gone():\n    pass\n",
    "mosp/proxy.py": (
        '__all__ = ["anything"]\ndef __getattr__(name):\n    return name\n'
    ),
}
APP_A = {
    "app/__init__.py": "",
    "app/main.py": (
        "import mosp.host\n"
        'mosp.host.bind(hooks="app.hooks")\n'
        "from mosp.api import router, fold, Parser\n"
        "from mosp import proxy\n"
        "Parser().used_method()\n"
        "value = proxy.anything\n"
    ),
    "app/hooks.py": "def limit():\n    return 1\n",
}
APP_B = {
    "app/__init__.py": "",
    "app/main.py": "from mosp.api import lazy, CONSTANT\n",
}
TESTS = {"test_api.py": "from mosp.api import helper_only_tests\n"}


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def _analyse(tmp_path, coverage_files=()):
    framework = _write(tmp_path / "framework", FRAMEWORK) / "mosp"
    a = _write(tmp_path / "a", APP_A) / "app"
    b = _write(tmp_path / "b", APP_B) / "app"
    tests = _write(tmp_path / "tests", TESTS)
    return framework, tool.analyse(
        framework, {"a": [a], "b": [b]}, [tests], list(coverage_files)
    )


def test_what_no_application_reaches_is_listed(tmp_path):
    _, (_, unused, tested, _, _, _, _) = _analyse(tmp_path)
    assert unused == {
        "mosp.dead:",
        "mosp.names:unused_helper",
        "mosp.api:helper_only_tests",
        # mosp calls the hook machinery, but nothing calls this helper.
        "mosp.host.hooks:page",
    }
    # Only mosp's own tests keep this one.
    assert "mosp.api:helper_only_tests" in tested
    assert "mosp.names:unused_helper" not in tested


def test_reexports_decorators_lazy_imports_and_module_hooks_are_followed(tmp_path):
    framework, (index, unused, *_rest) = _analyse(tmp_path)
    edges, registered_by = tool.graph(index)
    reached = tool.reachable(
        edges, registered_by, tool.tree_references(index, [tmp_path / "a" / "app"])
    )
    # The route is registered on the router the application includes, and
    # its body reaches the hook it calls.
    assert {"mosp.api:endpoint", "mosp.host.hooks:limit"} <= reached
    # "fold" was imported through mosp.api, and is mosp.names' own.
    assert "mosp.names:fold" in reached
    # Python calls a module's __getattr__ itself.
    assert {"mosp.proxy:__getattr__", "mosp.proxy:__all__"} <= reached
    # The other application reaches fold through an import in a function.
    assert "mosp.names:fold" not in unused


def test_a_module_passed_on_as_a_value_reaches_all_it_defines(tmp_path):
    # An application that iterates over modules calls what it reads from
    # each out of the analysis' sight, so all they define is reached; a
    # module named only as the base of a longer chain is not.
    _write(tmp_path / "framework", FRAMEWORK)
    index = tool.Index(tmp_path / "framework" / "mosp")
    app = _write(
        tmp_path / "app",
        {
            "app/__init__.py": "",
            "app/loop.py": (
                "from mosp import names\n"
                "from mosp import api\n"
                "for module in (names,):\n"
                "    module.fold('A')\n"
                "value = api.CONSTANT\n"
            ),
        },
    )
    reached = tool.tree_references(index, [app / "app"])
    assert {"mosp.names:fold", "mosp.names:unused_helper"} <= reached
    assert "mosp.api:CONSTANT" in reached
    assert "mosp.api:helper_only_tests" not in reached


def test_names_one_application_alone_reaches_are_listed_under_it(tmp_path):
    _, (*_rest, only) = _analyse(tmp_path)
    assert "mosp.api:endpoint" in only["a"]
    assert only["b"] == {"mosp.api:lazy", "mosp.api:CONSTANT"}
    # Reached by both: a imports it, and b's lazy import calls it.
    assert "mosp.names:fold" not in only["a"]
    # Both reach fold.
    assert not any("mosp.names:fold" in names for names in only.values())


def test_unused_methods_and_unprovided_hooks_are_listed(tmp_path):
    _, (_, _, _, _, methods, hooks, _) = _analyse(tmp_path)
    # handle_data is HTMLParser's to call; used_method is called.
    assert methods == {"mosp.api:Parser.stray"}
    assert hooks == {"pages"}


def test_reachable_code_no_application_ran_is_listed(tmp_path):
    from coverage import CoverageData

    framework = tmp_path / "framework" / "mosp"
    data = CoverageData(basename=str(tmp_path / "coverage"))
    _write(tmp_path / "framework", FRAMEWORK)
    data.add_lines({str((framework / "api.py").resolve()): [8]})
    data.write()

    _, (_, _, _, unrun, _, _, _) = _analyse(tmp_path, [tmp_path / "coverage"])

    assert "mosp.api:endpoint" not in unrun
    assert {"mosp.api:lazy", "mosp.names:fold", "mosp.api:Parser"} <= unrun


def test_the_report_names_each_kind(tmp_path, capsys):
    framework = _write(tmp_path / "framework", FRAMEWORK) / "mosp"
    _write(tmp_path / "a", APP_A)
    _write(tmp_path / "b", APP_B)
    _write(tmp_path / "tests", TESTS)

    tool.main(
        [
            "--mosp",
            str(framework),
            "--tests",
            str(tmp_path / "tests"),
            f"a={tmp_path / 'a' / 'app'}",
            f"b={tmp_path / 'b' / 'app'}",
        ]
    )

    out = capsys.readouterr().out
    assert "Unreachable from the applications: 4" in out
    assert "  mosp.dead\n    (the whole module)\n" in out
    assert "    helper_only_tests  (mosp's tests use it)\n" in out
    assert "Reached only by b: 2\n  mosp.api: CONSTANT, lazy\n" in out
    assert "Methods whose name nothing uses: 1\n  mosp.api:Parser.stray\n" in out
    assert (
        "Hooks no application provides (mosp's default always runs): 1\n  pages\n"
        in out
    )
