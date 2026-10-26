"""Mode enregistrement : écrit UNIQUEMENT des métadonnées dans un CSV local.

Colonnes : horodatage (epoch, s), ip du pair, taille de la charge utile (octets),
sens (« entrant » / « sortant »). Le contenu des paquets n'est JAMAIS écrit.
Fichiers : %LOCALAPPDATA%\\Guardian\\enregistrements\\session-AAAAMMJJ-HHMMSS.csv
Sert à ajuster plus tard les seuils de network/anomaly.py.
"""

from __future__ import annotations

import csv
import time
from pathlib import Path
from typing import Any, TextIO

from util.paths import data_dir

HEADER = ("horodatage", "ip", "taille", "sens")

# Limites d'un fichier d'enregistrement : au-delà, on passe à un nouveau fichier
# (rotation), et au-delà de MAX_FILES fichiers pour la même session, on arrête.
MAX_BYTES = 100 * 1024 * 1024
MAX_LINES = 1_000_000
MAX_FILES = 5


def recordings_dir() -> Path:
    path = data_dir() / "enregistrements"
    path.mkdir(parents=True, exist_ok=True)
    return path


class MetadataRecorder:
    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory or recordings_dir()
        self.path: Path | None = None
        self._file: TextIO | None = None
        self._writer: Any = None
        self.count = 0
        self.files = 0
        self.max_bytes = MAX_BYTES
        self.max_lines = MAX_LINES
        self.max_files = MAX_FILES
        self._bytes = 0
        self.stopped_by_limit = False

    @property
    def active(self) -> bool:
        return self._file is not None

    def start(self) -> Path:
        if self._file is None or self.path is None:
            self.files = 0
            self.stopped_by_limit = False
            self._open()
        if self.path is None:  # pragma: no cover - _open définit toujours path
            raise RuntimeError("enregistrement non démarré")
        return self.path

    def _open(self) -> None:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        self.files += 1
        suffix = "" if self.files == 1 else f"-{self.files}"
        self.path = self.directory / f"session-{stamp}{suffix}.csv"
        self._file = self.path.open("w", newline="", encoding="utf-8")
        self._writer = csv.writer(self._file)
        self._writer.writerow(HEADER)
        self.count = 0
        self._bytes = 0

    def write(self, ts: float, ip: str, size: int, inbound: bool) -> None:
        """N'accepte que des métadonnées (pas de bytes) : rien d'autre ne peut fuiter."""
        if self._writer is None:
            return
        row = (f"{ts:.6f}", str(ip), int(size), "entrant" if inbound else "sortant")
        self._writer.writerow(row)
        self.count += 1
        self._bytes += sum(len(str(v)) for v in row) + len(row) + 1  # approx.
        if self.count >= self.max_lines or self._bytes >= self.max_bytes:
            self._close()
            if self.files < self.max_files:
                self._open()
            else:
                self.stopped_by_limit = True

    def stop(self) -> None:
        self._close()

    def _close(self) -> None:
        if self._file is not None:
            self._file.close()
        self._file = None
        self._writer = None
