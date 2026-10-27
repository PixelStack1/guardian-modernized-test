"""Mode d'acceptation CI (lot 8) — inerte en usage normal.

``--ci-probe <fichier.json>`` n'est utilisé QUE par le banc Windows de la CI
(tests/windows/acceptance.py). Sans ce drapeau, rien ne change. Le drapeau est IGNORÉ (protection
normale, une ligne de log) sauf si ``GUARDIAN_CI_PROBE=1`` ET ``CI=true`` (ou
``GITHUB_ACTIONS=true``) sont présents dans l'environnement. Avec lui :

- mode « à blanc » : le filtre WinDivert devient ``false`` (aucun paquet capturé,
  donc aucun ``w.send`` : le pilote est chargé et un handle est ouvert, mais aucun
  trafic n'est lu ni réinjecté) ; transmis aux processus enfants par la variable
  d'environnement ``GUARDIAN_CI_DRY=1`` ;
- la GUI écrit périodiquement son état (statut, raccourcis, SHA256 affiché…) dans
  le fichier JSON donné, pour que le banc le lise.

Aucune donnée réseau n'est écrite dans la sonde. Voir docs/ci-acceptance.md.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

CI_PROBE_FLAG = "--ci-probe"
DRY_ENV = "GUARDIAN_CI_DRY"
DRY_FILTER = "false"  # langage de filtre WinDivert : ne correspond à aucun paquet


def probe_path(argv: list[str]) -> Path | None:
    """Chemin passé après ``--ci-probe`` (None si absent ou vide)."""
    try:
        i = argv.index(CI_PROBE_FLAG)
    except ValueError:
        return None
    if i + 1 >= len(argv) or not argv[i + 1] or argv[i + 1].startswith("--"):
        return None
    return Path(argv[i + 1])


PROBE_ENV = "GUARDIAN_CI_PROBE"
CI_ENVS = ("CI", "GITHUB_ACTIONS")


def probe_allowed(env: Mapping[str, str] | None = None) -> bool:
    """Le drapeau n'est honoré que si GUARDIAN_CI_PROBE=1 ET (CI ou GITHUB_ACTIONS)=true."""
    e = os.environ if env is None else env
    if e.get(PROBE_ENV) != "1":
        return False
    return any(e.get(k, "").strip().lower() == "true" for k in CI_ENVS)


def enable_dry() -> None:
    os.environ[DRY_ENV] = "1"


def dry() -> bool:
    return os.environ.get(DRY_ENV) == "1"


# Jalons de démarrage (horodatages, aucune donnée réseau) : relevés toujours (coût
# négligeable), mais seule la sonde CI les écrit. Inerte en usage normal.
MARKS: dict[str, float] = {}


def mark(name: str) -> None:
    import time

    MARKS.setdefault(name, time.time())


def process_start_time() -> float | None:
    """Création de CE processus (GetProcessTimes), en secondes epoch ; None sinon."""
    try:
        import ctypes
        from ctypes import wintypes as wt

        k32 = ctypes.WinDLL("kernel32")
        k32.GetCurrentProcess.restype = wt.HANDLE
        k32.GetProcessTimes.argtypes = [wt.HANDLE] + [ctypes.POINTER(wt.FILETIME)] * 4
        c, e, k, u = (wt.FILETIME() for _ in range(4))
        if not k32.GetProcessTimes(
            k32.GetCurrentProcess(),
            ctypes.byref(c),
            ctypes.byref(e),
            ctypes.byref(k),
            ctypes.byref(u),
        ):
            return None
        ft = (c.dwHighDateTime << 32) | c.dwLowDateTime
        return ft / 1e7 - 11644473600.0
    except Exception:
        return None
