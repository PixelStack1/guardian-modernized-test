"""Persistance des blocages du bouclier AUTO dans un fichier séparé.

``%LOCALAPPDATA%\\Guardian\\auto_block.json`` : ``{"ip": expiration_epoch, ...}``.
Jamais mélangé à la Blacklist de data.json (blocages manuels, touche B).
Écriture atomique (.tmp + os.replace) dans un thread dédié ; toute erreur
d'E/S ou de JSON est absorbée (fichier corrompu = liste vide).
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import logging
import math
import os
import threading
from collections.abc import Callable
from pathlib import Path

from util.paths import data_dir

logger = logging.getLogger(__name__)

FILE_NAME = "auto_block.json"
# Nombre maximal d'entrées conservées (les plus proches de l'expiration partent d'abord).
MAX_ENTRIES = 5000


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


def _valid_expiry(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value > 0
    )


def cap(entries: dict[str, float], limit: int = MAX_ENTRIES) -> dict[str, float]:
    """Garde les ``limit`` entrées qui expirent le plus tard."""
    if len(entries) <= limit:
        return dict(entries)
    kept = sorted(entries.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    return dict(kept)


def load(
    now: float,
    guard: Callable[[str], bool] | None = None,
    path: Path | None = None,
    limit: int = MAX_ENTRIES,
) -> dict[str, float]:
    """Charge, valide, purge (expirés), filtre (garde-fous) et plafonne. Ne lève jamais."""
    try:
        path = path or store_path()
        if not path.exists():
            return {}
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:  # E/S, JSON corrompu, encodage...
        logger.warning("auto_block.json ignoré : %s", e)
        return {}
    if not isinstance(raw, dict):
        return {}
    entries: dict[str, float] = {}
    for ip, expiry in raw.items():
        if not _valid_ip(ip) or not _valid_expiry(expiry) or expiry <= now:
            continue
        if guard is not None:
            try:
                if guard(ip):
                    continue
            except Exception:
                continue
        entries[ip] = float(expiry)
    return cap(entries, limit)


def save(entries: dict[str, float], path: Path | None = None) -> bool:
    """Écriture atomique ; renvoie False en cas d'échec (jamais d'exception)."""
    tmp: Path | None = None
    try:
        path = path or store_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(
            json.dumps(cap(entries), indent=1, sort_keys=True), encoding="utf-8"
        )
        os.replace(tmp, path)
        return True
    except Exception as e:
        logger.warning("Écriture de auto_block.json impossible : %s", e)
        if tmp is not None:
            with contextlib.suppress(OSError):
                tmp.unlink(missing_ok=True)
        return False


class AutoBlockSaver:
    """Enregistre en arrière-plan le DERNIER état demandé (les demandes rapprochées
    sont fusionnées). Aucune écriture disque dans la boucle d'affichage/capture."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._pending: dict[str, float] | None = None
        self._wake = threading.Event()
        self._stop = False
        self.saves = 0
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def request(self, entries: dict[str, float]) -> None:
        with self._lock:
            self._pending = dict(entries)
        self._wake.set()

    def _run(self) -> None:
        while True:
            self._wake.wait()
            with self._lock:
                pending, self._pending = self._pending, None
                self._wake.clear()
                stop = self._stop
            if pending is not None and save(pending, self.path):
                self.saves += 1
            if stop:
                return

    def close(self, timeout: float = 5.0) -> None:
        with self._lock:
            self._stop = True
        self._wake.set()
        self._thread.join(timeout)
