"""Diagnostic au démarrage (lot 7) : droits admin, WinDivert, configuration.

Lecture seule : aucune écriture, aucun accès au jeu ni au réseau. Chaque vérification
renvoie un ``Check`` ; une erreur inattendue devient un échec, jamais une exception.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from util.i18n import t


@dataclass(frozen=True)
class Check:
    key: str  # clé i18n du libellé
    ok: bool | None  # None = non vérifiable (hors Windows)
    detail: str = ""

    def label(self) -> str:
        return t(self.key)

    def state(self) -> str:
        if self.ok is None:
            return t("health.unknown")
        return t("health.ok") if self.ok else t("health.fail")


def _windows_is_admin() -> bool | None:
    if sys.platform != "win32":
        return None
    import ctypes

    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def check_admin(is_admin: Callable[[], bool | None] | None = None) -> Check:
    try:
        ok = (is_admin or _windows_is_admin)()
    except Exception as e:
        return Check("health.admin", False, str(e))
    if ok is None:
        return Check("health.admin", None, t("health.not_windows"))
    return Check("health.admin", ok, "" if ok else t("health.no_admin"))


def _verify_windivert() -> Any:
    from util.integrity import verify_windivert

    return verify_windivert()


def check_windivert(verify: Callable[[], Any] | None = None) -> Check:
    """WinDivert64.dll/.sys présents et identiques à la publication officielle."""
    try:
        (verify or _verify_windivert)()
    except Exception as e:
        return Check("health.windivert", False, str(e))
    return Check("health.windivert", True)


def _config_path() -> Path:
    from util.paths import data_file

    return data_file("data.json")


def check_config(path: Path | None = None) -> Check:
    """data.json lisible et au bon format (un objet JSON). Absent = OK (créé)."""
    try:
        p = path or _config_path()
        if not p.exists():
            return Check("health.config", True, t("health.missing_config"))
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return Check("health.config", False, "data.json : objet JSON attendu")
        return Check("health.config", True, str(p))
    except Exception as e:
        return Check("health.config", False, str(e))


def run_checks(
    is_admin: Callable[[], bool | None] | None = None,
    verify: Callable[[], Any] | None = None,
    config_path: Path | None = None,
) -> tuple[Check, ...]:
    return (
        check_admin(is_admin),
        check_windivert(verify),
        check_config(config_path),
    )


def problems(checks: tuple[Check, ...]) -> int:
    return sum(1 for c in checks if c.ok is False)
