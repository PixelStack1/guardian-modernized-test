"""Per-user data directory: %LOCALAPPDATA%\\Guardian on Windows (fallback: ~/Guardian elsewhere).

No file is ever read or migrated from the current working directory.
"""

from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    path = (Path(base) if base else Path.home()) / "Guardian"
    path.mkdir(parents=True, exist_ok=True)
    return path


def data_file(name: str) -> Path:
    """Absolute path of a data/log/cache file inside data_dir()."""
    return data_dir() / name
