"""Per-user data directory: %LOCALAPPDATA%\\Guardian on Windows (fallback: ~/Guardian elsewhere).

No file is ever read or migrated from the current working directory.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if base:
        path = Path(base) / "Guardian"
    elif sys.platform == "win32":
        # Lot 3 (F4) : LOCALAPPDATA absent -> emplacement standard, jamais
        # Documents/Images/Musique/Vidéos.
        path = Path.home() / "AppData" / "Local" / "Guardian"
    else:
        path = Path.home() / "Guardian"
    path.mkdir(parents=True, exist_ok=True)
    return path


def data_file(name: str) -> Path:
    """Absolute path of a data/log/cache file inside data_dir()."""
    return data_dir() / name
