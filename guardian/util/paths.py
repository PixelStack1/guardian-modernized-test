"""Per-user data directory: %LOCALAPPDATA%\\Guardian on Windows (fallback: ~/Guardian on non-Windows)."""

from __future__ import annotations

import os
import shutil
from pathlib import Path


def data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    path = (Path(base) if base else Path.home()) / "Guardian"
    path.mkdir(parents=True, exist_ok=True)
    return path


def data_file(name: str) -> Path:
    """Path of a data/log file; migrates a legacy copy from the current directory once."""
    target = data_dir() / name
    legacy = Path.cwd() / name
    if (
        not target.exists()
        and legacy.is_file()
        and legacy.resolve() != target.resolve()
    ):
        shutil.copy2(legacy, target)
    return target
