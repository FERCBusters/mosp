#!/usr/bin/env python3
"""Move an application's myf dependency to a myf commit.

Usage: bump_pin.py CHECKOUT COMMIT REPORT_DIR

Every pyproject.toml under CHECKOUT that declares myf as a git dependency of
FERCBusters/myf has its ``rev`` set to COMMIT (a full commit hash). The tool
writes to REPORT_DIR, for the workflow that proposes the change:

- outputs.txt: ``changed=true|false`` and ``previous=<rev>`` (the first pin
  found, empty when none), in GitHub Actions output form;
- projects.txt: each changed project's directory, one per line, relative to
  CHECKOUT, for ``poetry lock`` to run in;
- commit-message.txt and pr-body.md: the proposal's text.

An application that does not use myf yet, or already pins COMMIT, is left
unchanged.
"""

import re
import sys
from pathlib import Path

# The line declaring myf in [tool.poetry.dependencies]: an inline table naming
# the myf repository and a rev.
_PIN = re.compile(
    r'^(?P<head>myf\s*=\s*\{[^}\n]*git\s*=\s*"https://github\.com/FERCBusters/myf'
    r'(?:\.git)?"[^}\n]*rev\s*=\s*")(?P<rev>[^"\n]*)(?P<tail>"[^}\n]*\})',
    re.MULTILINE,
)
_COMMIT = re.compile(r"[0-9a-f]{40}")
_SKIPPED = {".git", ".venv", "node_modules"}


def projects(checkout: Path) -> list[Path]:
    """Every pyproject.toml under checkout that pins myf, in path order."""
    found = []
    for path in sorted(checkout.rglob("pyproject.toml")):
        if _SKIPPED.intersection(path.relative_to(checkout).parts):
            continue
        if _PIN.search(path.read_text(encoding="utf-8")):
            found.append(path)
    return found


def bump(checkout: Path, commit: str) -> tuple[list[Path], str]:
    """Pin myf at commit; the projects changed and the first earlier pin."""
    if not _COMMIT.fullmatch(commit):
        raise ValueError("commit must be a full lowercase commit hash")
    changed, previous = [], ""
    for path in projects(checkout):
        text = path.read_text(encoding="utf-8")
        match = _PIN.search(text)
        assert match is not None
        previous = previous or match["rev"]
        if match["rev"] == commit:
            continue
        path.write_text(
            _PIN.sub(lambda m: m["head"] + commit + m["tail"], text, count=1),
            encoding="utf-8",
        )
        changed.append(path.parent.relative_to(checkout))
    return changed, previous


def report(changed: list[Path], previous: str, commit: str, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "outputs.txt").write_text(
        f"changed={'true' if changed else 'false'}\nprevious={previous}\n"
    )
    (out / "projects.txt").write_text("".join(f"{p.as_posix()}\n" for p in changed))
    short = commit[:12]
    (out / "commit-message.txt").write_text(
        f"Move myf to {short}\n\nPins myf at FERCBusters/myf@{commit} and "
        "updates the lock file.\n"
    )
    compare = (
        f"https://github.com/FERCBusters/myf/compare/{previous}...{commit}"
        if _COMMIT.fullmatch(previous)
        else f"https://github.com/FERCBusters/myf/commit/{commit}"
    )
    listed = "".join(f"- `{p.as_posix()}`\n" for p in changed)
    (out / "pr-body.md").write_text(
        f"Moves myf to FERCBusters/myf@{commit}, the head of myf's main branch "
        f"after its CI passed.\n\nChanges in myf: {compare}\n\n"
        f"Projects updated (pyproject.toml and poetry.lock):\n\n{listed}\n"
        "This pull request was opened by myf's bump workflow. It never merges "
        "itself: this repository's CI runs on it, and a maintainer reviews and "
        "merges it.\n"
    )


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    checkout, commit, out = Path(argv[1]), argv[2], Path(argv[3])
    try:
        changed, previous = bump(checkout, commit)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2
    report(changed, previous, commit, out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
