"""The README badges: coverage, mypy and ruff, rendered from mosp CI's reports.

tools/coverage_badges.py reads the reports from a downloaded CI artifact, so
these tests build such a directory and check what each badge says, and hold
the CI workflow to writing the reports the badges read.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLEAN_MYPY = "Success: no issues found in 73 source files\n"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "coverage_badges", ROOT / "tools" / "coverage_badges.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


badges = _load_tool()


def results(tmp_path, *, coverage=100.0, mypy=CLEAN_MYPY, ruff="[]"):
    """A CI artifact laid out as the upload step writes it."""
    root = tmp_path / "results"
    root.mkdir()
    (root / "coverage.json").write_text(
        json.dumps({"totals": {"percent_covered": coverage}})
    )
    (root / "mypy-report.txt").write_text(mypy)
    (root / "ruff-findings.json").write_text(ruff)
    return root


def rendered(tmp_path, **reports):
    out = tmp_path / "badges"
    badges.main(["coverage_badges.py", str(results(tmp_path, **reports)), str(out)])
    return {path.name: path.read_text() for path in sorted(out.glob("*.svg"))}


def test_a_clean_run_renders_three_passing_badges(tmp_path):
    svgs = rendered(tmp_path)
    assert sorted(svgs) == ["coverage.svg", "mypy.svg", "ruff.svg"]
    assert 'aria-label="coverage: 100%"' in svgs["coverage.svg"]
    assert 'aria-label="mypy: 0 errors"' in svgs["mypy.svg"]
    assert 'aria-label="ruff: 0 issues"' in svgs["ruff.svg"]
    assert all('fill="#4c1"' in svg for svg in svgs.values())


@pytest.mark.parametrize(
    "percent,colour",
    [(85.0, "#97ca00"), (75.0, "#a4a61d"), (65.0, "#dfb317"), (10.0, "#e05d44")],
)
def test_lower_coverage_is_shown_in_warmer_colours(tmp_path, percent, colour):
    svgs = rendered(tmp_path, coverage=percent)
    assert f'fill="{colour}"' in svgs["coverage.svg"]


def test_findings_are_counted_and_shown_as_failing(tmp_path):
    mypy = (
        "mosp/a.py:3: error: Incompatible return value type  [return-value]\n"
        "mosp/b.py:9: error: Name 'x' is not defined  [name-defined]\n"
        "Found 2 errors in 2 files (checked 73 source files)\n"
    )
    ruff = json.dumps([{"code": "F401"}])
    svgs = rendered(tmp_path, mypy=mypy, ruff=ruff)
    assert 'aria-label="mypy: 2 errors"' in svgs["mypy.svg"]
    assert 'aria-label="ruff: 1 issue"' in svgs["ruff.svg"]
    assert 'fill="#e05d44"' in svgs["mypy.svg"] and 'fill="#e05d44"' in svgs["ruff.svg"]


@pytest.mark.parametrize(
    "summary,errors",
    [
        ("Success: no issues found in 1 source file", 0),
        ("Found 1 error in 1 file (checked 1 source file)", 1),
        ("Found 12 errors in 3 files (checked 73 source files)", 12),
    ],
)
def test_the_mypy_count_comes_from_its_summary_line(summary, errors):
    assert (
        badges.mypy_errors("mosp/x.py:1: note: detail\n" + summary + "\n\n") == errors
    )


@pytest.mark.parametrize(
    "reports,refusal",
    [
        ({"mypy": ""}, "without a summary"),
        ({"mypy": "mosp/x.py:1: error: boom  [misc]\n"}, "without a summary"),
        ({"ruff": '{"findings": []}'}, "not a list"),
        ({"coverage": "100"}, "not a number"),
        ({"coverage": True}, "not a number"),
        ({"coverage": 101}, "out of range"),
    ],
)
def test_a_report_the_badges_cannot_read_stops_the_publish(tmp_path, reports, refusal):
    with pytest.raises(SystemExit, match=refusal):
        rendered(tmp_path, **reports)


def test_a_missing_report_stops_the_publish(tmp_path):
    root = results(tmp_path)
    (root / "mypy-report.txt").unlink()
    with pytest.raises(SystemExit, match="mypy-report.txt"):
        badges.main(["coverage_badges.py", str(root), str(tmp_path / "out")])


def test_the_tool_takes_two_directories(tmp_path):
    with pytest.raises(SystemExit, match="Usage"):
        badges.main(["coverage_badges.py"])


def test_ci_writes_the_reports_the_badges_read():
    workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text()
    assert "--output-file test-results/ruff-findings.json" in workflow
    assert "poetry run mypy | tee test-results/mypy-report.txt" in workflow
    assert "--cov-report=json:test-results/coverage.json" in workflow
    assert "name: mosp-test-results" in workflow
    # The type check's pipe keeps mypy's exit status.
    types = workflow.split("- name: Check Python types", 1)[1].split("- name:", 1)[0]
    assert "set -o pipefail" in types
    publish = (ROOT / ".github" / "workflows" / "coverage-badges.yml").read_text()
    assert 'workflows: ["mosp CI"]' in publish
    assert "name: mosp-test-results" in publish
