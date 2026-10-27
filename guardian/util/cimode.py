"""Mode d'acceptation CI (lot 8) — inerte en usage normal.

``--ci-probe <fichier.json>`` n'est utilisé QUE par le banc Windows de la CI
(tests/windows/acceptance.py). Sans ce drapeau, rien ne change. Avec lui :

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


def enable_dry() -> None:
    os.environ[DRY_ENV] = "1"


def dry() -> bool:
    return os.environ.get(DRY_ENV) == "1"
