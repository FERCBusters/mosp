"""mosp's own modules, scanned by the source contracts."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

import mosp

SOURCES = Path(mosp.__file__).resolve().parent


def name_in(path: Path, root: Path) -> PurePosixPath:
    return PurePosixPath(path.relative_to(root).as_posix())
