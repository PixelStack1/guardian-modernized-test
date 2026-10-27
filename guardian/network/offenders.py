"""Récidivistes : IP déjà bloquées (bouclier auto ou touche B), mémorisées localement.

``%LOCALAPPDATA%\\Guardian\\recidivistes.json`` :
``{"ip": {"first": epoch, "last": epoch, "count": n, "reason": "..."}, ...}``.
MÉTADONNÉES SEULEMENT (jamais de contenu de paquet), taille bornée (MAX_ENTRIES,
les moins récemment bloquées partent d'abord). Écriture atomique (.tmp +
os.replace) ; toute erreur d'E/S ou de JSON est absorbée (fichier corrompu =
liste vide). Aucun appel réseau. Les serveurs Rockstar ne sont jamais enregistrés
(filtre ``guard``).
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import logging
import math
import os
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

from util.paths import data_dir

logger = logging.getLogger(__name__)

FILE_NAME = "recidivistes.json"
MAX_ENTRIES = 2000
MAX_REASON = 64
# Lot 3 (F3) : fichier plus gros ignoré (liste vide + avertissement).
MAX_FILE_BYTES = 2 * 1024 * 1024


@dataclass
class Offender:
    first: float
    last: float
    count: int
    reason: str


def store_path() -> Path:
    return data_dir() / FILE_NAME


def _valid_ip(ip: object) -> bool:
    if not isinstance(ip, str):
        return False
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return True


def _num(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
    )


def _parse(value: object) -> Offender | None:
    if not isinstance(value, dict):
        return None
    first, last, count, reason = (
        value.get("first"),
        value.get("last"),
        value.get("count"),
        value.get("reason", ""),
    )
    if not (_num(first) and _num(last) and isinstance(count, int)) or count < 1:
        return None
    if isinstance(count, bool) or not isinstance(reason, str):
        return None
    assert isinstance(first, (int, float)) and isinstance(last, (int, float))
    # Lot 3 (F2) : caractères de contrôle/ANSI retirés.
    reason = "".join(c for c in reason if c.isprintable())
    return Offender(float(first), float(last), count, reason[:MAX_REASON])


class OffenderStore:
    """Liste bornée ip -> Offender. ``path=None`` et ``persist=False`` : mémoire seule
    (rejeu). ``guard(ip)`` vrai = jamais enregistré (serveurs Rockstar)."""

    def __init__(
        self,
        path: Path | None = None,
        persist: bool = True,
        guard: Callable[[str], bool] | None = None,
        limit: int = MAX_ENTRIES,
    ) -> None:
        self.path = path
        self.persist = persist
        self.guard = guard or (lambda _ip: False)
        self.limit = limit
        self.entries: dict[str, Offender] = {}
        if persist:
            self.entries = self._load()

    def _file(self) -> Path:
        return self.path or store_path()

    def _excluded(self, ip: str) -> bool:
        try:
            return bool(self.guard(ip))
        except Exception:
            return True  # dans le doute, ne rien enregistrer

    def _load(self) -> dict[str, Offender]:
        try:
            path = self._file()
            if not path.exists():
                return {}
            if path.stat().st_size > MAX_FILE_BYTES:
                logger.warning(
                    "%s ignoré : plus de %d octets", FILE_NAME, MAX_FILE_BYTES
                )
                return {}
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning("%s ignoré : %s", FILE_NAME, e)
            return {}
        if not isinstance(raw, dict):
            return {}
        out: dict[str, Offender] = {}
        for ip, value in raw.items():
            entry = _parse(value)
            if entry is not None and _valid_ip(ip) and not self._excluded(ip):
                out[ip] = entry
        return self._cap(out)

    def _cap(self, entries: dict[str, Offender]) -> dict[str, Offender]:
        if len(entries) <= self.limit:
            return entries
        kept = sorted(entries.items(), key=lambda kv: kv[1].last, reverse=True)
        return dict(kept[: self.limit])

    def save(self) -> bool:
        """Écriture atomique ; False en cas d'échec (jamais d'exception)."""
        if not self.persist:
            return True
        tmp: Path | None = None
        try:
            path = self._file()
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(path.name + ".tmp")
            data = {ip: asdict(e) for ip, e in self.entries.items()}
            tmp.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
            os.replace(tmp, path)
            return True
        except Exception as e:
            logger.warning("Écriture de %s impossible : %s", FILE_NAME, e)
            if tmp is not None:
                with contextlib.suppress(OSError):
                    tmp.unlink(missing_ok=True)
            return False

    def __contains__(self, ip: object) -> bool:
        return ip in self.entries

    def __len__(self) -> int:
        return len(self.entries)

    def ips(self) -> list[str]:
        return list(self.entries)

    def get(self, ip: str) -> Offender | None:
        return self.entries.get(ip)

    def record(self, ip: str, reason: str, now: float) -> bool:
        """Enregistre un blocage ; False si refusé (IP invalide ou protégée)."""
        if not _valid_ip(ip) or self._excluded(ip):
            return False
        entry = self.entries.get(ip)
        if entry is None:
            self.entries[ip] = Offender(now, now, 1, reason[:MAX_REASON])
        else:
            entry.last = now
            entry.count += 1
            entry.reason = reason[:MAX_REASON]
        self.entries = self._cap(self.entries)
        self.save()
        return ip in self.entries

    def remove(self, ip: str) -> bool:
        if self.entries.pop(ip, None) is None:
            return False
        self.save()
        return True
