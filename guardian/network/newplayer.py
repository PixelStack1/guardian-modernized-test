"""Alerte « nouveau joueur » + journal local (métadonnées uniquement).

Chaque nouvelle IP (hors serveurs Rockstar) vue dans la session déclenche une ligne
d'alerte dans la vue et une ligne dans
%LOCALAPPDATA%\\Guardian\\journal\\joueurs.log : heure, IP, pays (base GeoIP locale,
aucun appel réseau) et ping s'il est connu (Guardian ne mesure pas de ping aujourd'hui :
champ omis). Seuls les paquets ENTRANTS comptent (IP du pair = source), comme le
compteur de joueurs. Jamais de contenu de paquet. Fichier borné avec rotation.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from util.geoip import country_code
from util.paths import data_dir

JOURNAL_NAME = "joueurs.log"
MAX_BYTES = 1024 * 1024  # 1 Mo par fichier
BACKUPS = 3  # joueurs.log.1 .. .3
MAX_TRACKED = 4096  # borne mémoire des IP déjà vues dans la session

logger = logging.getLogger(__name__)


def journal_dir() -> Path:
    path = data_dir() / "journal"
    path.mkdir(parents=True, exist_ok=True)
    return path


def format_line(
    ts: float, ip: str, country: str | None, ping_ms: float | None = None
) -> str:
    try:
        stamp = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        stamp = "????-??-?? ??:??:??"
    parts = [stamp, ip, country or "—"]
    if ping_ms is not None:
        parts.append(f"{ping_ms:.0f} ms")
    return "  ".join(parts)


class PlayerJournal:
    """Fichier texte borné : au-delà de ``max_bytes``, rotation (``backups`` anciens)."""

    def __init__(
        self,
        directory: Path | None = None,
        max_bytes: int = MAX_BYTES,
        backups: int = BACKUPS,
    ) -> None:
        self.directory = directory
        self.max_bytes = max_bytes
        self.backups = backups

    @property
    def path(self) -> Path:
        directory = self.directory or journal_dir()
        directory.mkdir(parents=True, exist_ok=True)
        return directory / JOURNAL_NAME

    def _rotate(self, path: Path) -> None:
        for i in range(self.backups, 0, -1):
            src = path if i == 1 else path.with_name(f"{path.name}.{i - 1}")
            dst = path.with_name(f"{path.name}.{i}")
            if src.exists():
                src.replace(dst)
        if self.backups <= 0:
            path.unlink(missing_ok=True)

    def write(self, line: str) -> None:
        """Ne lève jamais : un journal ne doit pas gêner la protection."""
        try:
            path = self.path
            data = (line.replace("\n", " ") + "\n").encode("utf-8")
            if path.exists() and path.stat().st_size + len(data) > self.max_bytes:
                self._rotate(path)
            with path.open("ab") as f:
                f.write(data)
        except Exception:
            logger.debug("journal joueurs : écriture impossible", exc_info=True)


class NewPlayerTracker:
    """Détecte la première apparition d'une IP de joueur dans la session."""

    def __init__(
        self,
        is_server: Callable[[str], bool],
        journal: PlayerJournal | None = None,
        alert: Callable[[str, str], str] | None = None,
        max_tracked: int = MAX_TRACKED,
    ) -> None:
        self.is_server = is_server
        self.journal = journal
        self.alert = alert or (lambda ip, cc: f"Nouveau joueur : {ip} ({cc})")
        self.max_tracked = max_tracked
        self.seen: dict[str, None] = {}

    def observe(
        self, ts: float, ip: str, inbound: bool, ping_ms: float | None = None
    ) -> str | None:
        """Renvoie la ligne d'alerte si ``ip`` est un nouveau joueur, sinon None."""
        if not inbound or ip in self.seen:
            return None
        try:
            if self.is_server(ip):
                return None
        except Exception:
            return None
        if len(self.seen) >= self.max_tracked:
            del self.seen[next(iter(self.seen))]
        self.seen[ip] = None
        cc = country_code(ip)
        if self.journal is not None:
            with contextlib.suppress(Exception):
                self.journal.write(format_line(ts, ip, cc, ping_ms))
        return self.alert(ip, cc or "—")
