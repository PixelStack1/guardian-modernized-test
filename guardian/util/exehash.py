"""SHA256 de l'exécutable en cours (lot 7), affiché dans les Réglages.

Lecture seule du fichier du programme lui-même (jamais du jeu). Calculé une fois.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from util.integrity import sha256_file


@dataclass(frozen=True)
class ExeHash:
    path: str
    sha256: str  # "" si non compilé ou erreur
    frozen: bool
    error: str = ""


def running_exe() -> tuple[Path, bool]:
    """(chemin, compilé ?) : sys.executable pour un exe PyInstaller."""
    frozen = bool(getattr(sys, "frozen", False))
    return Path(sys.executable).resolve(), frozen


def compute(path: Path, frozen: bool) -> ExeHash:
    if not frozen:
        return ExeHash(str(path), "", False)
    try:
        return ExeHash(str(path), sha256_file(path), True)
    except Exception as e:
        return ExeHash(str(path), "", True, str(e))


@lru_cache(maxsize=1)
def current() -> ExeHash:
    return compute(*running_exe())
