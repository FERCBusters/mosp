"""tools/bump_pin.py: moving an application's myf pin to a new myf commit,
as the bump workflow does for KEEN, MIDENA and OSPMAE."""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
OLD = "23ffc38898b6df55c53e46e9a3c17325881389c2"
NEW = "fa79892cd9d7ef6c6459efb139b5be25a6ad241f"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "bump_pin", ROOT / "tools" / "bump_pin.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


bump_pin = _load_tool()


def _pyproject(rev, *, url="https://github.com/FERCBusters/myf.git"):
    return (
        "[tool.poetry.dependencies]\n"
        'python = "^3.13"\n'
        f'myf = {{ git = "{url}", rev = "{rev}" }}\n'
        'fastapi = "^0.141"\n'
    )


@pytest.fixture()
def checkout(tmp_path):
    api = tmp_path / "services" / "api"
    api.mkdir(parents=True)
    (api / "pyproject.toml").write_text(_pyproject(OLD))
    # Copies the tool never edits: dependencies and environments.
    for ignored in (".venv/lib", "node_modules/x", ".git/y"):
        folder = tmp_path / ignored
        folder.mkdir(parents=True)
        (folder / "pyproject.toml").write_text(_pyproject(OLD))
    return tmp_path


def test_the_pin_moves_and_nothing_else_changes(checkout, tmp_path):
    out = tmp_path / "report"
    assert bump_pin.main(["bump_pin.py", str(checkout), NEW, str(out)]) == 0

    pyproject = checkout / "services/api/pyproject.toml"
    assert pyproject.read_text() == _pyproject(NEW)
    assert (checkout / ".venv/lib/pyproject.toml").read_text() == _pyproject(OLD)
    assert (out / "outputs.txt").read_text() == f"changed=true\nprevious={OLD}\n"
    assert (out / "projects.txt").read_text() == "services/api\n"
    assert (
        (out / "commit-message.txt").read_text().startswith(f"Move myf to {NEW[:12]}\n")
    )
    body = (out / "pr-body.md").read_text()
    assert f"https://github.com/FERCBusters/myf/compare/{OLD}...{NEW}" in body
    assert "- `services/api`" in body


def test_an_application_already_at_the_commit_is_left_alone(checkout, tmp_path):
    bump_pin.bump(checkout, NEW)
    changed, previous = bump_pin.bump(checkout, NEW)
    assert (changed, previous) == ([], NEW)
    bump_pin.report(changed, previous, NEW, tmp_path / "report")
    assert (tmp_path / "report/outputs.txt").read_text() == (
        f"changed=false\nprevious={NEW}\n"
    )


def test_an_application_without_myf_is_left_alone(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.poetry]\nname = "ospmae"\n')
    (tmp_path / "other").mkdir()
    (tmp_path / "other/pyproject.toml").write_text(
        _pyproject(OLD, url="https://github.com/elsewhere/myf.git")
    )
    assert bump_pin.bump(tmp_path, NEW) == ([], "")
    bump_pin.report([], "", NEW, tmp_path / "report")
    body = (tmp_path / "report/pr-body.md").read_text()
    assert f"https://github.com/FERCBusters/myf/commit/{NEW}" in body


@pytest.mark.parametrize("commit", ["main", NEW[:12], NEW.upper(), NEW + "0"])
def test_only_a_full_commit_hash_is_pinned(checkout, tmp_path, commit, capsys):
    out = tmp_path / "report"
    assert bump_pin.main(["bump_pin.py", str(checkout), commit, str(out)]) == 2
    assert "full lowercase commit hash" in capsys.readouterr().err
    assert not out.exists()
    assert OLD in (checkout / "services/api/pyproject.toml").read_text()


def test_the_usage_is_printed_for_the_wrong_arguments(capsys):
    assert bump_pin.main(["bump_pin.py"]) == 2
    assert "Usage: bump_pin.py" in capsys.readouterr().err
