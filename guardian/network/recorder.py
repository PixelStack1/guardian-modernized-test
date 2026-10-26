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

    @property
    def active(self) -> bool:
        return self._file is not None

    def start(self) -> Path:
        if self._file is None:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            self.path = self.directory / f"session-{stamp}.csv"
            self._file = self.path.open("w", newline="", encoding="utf-8")
            self._writer = csv.writer(self._file)
            self._writer.writerow(HEADER)
            self.count = 0
        assert self.path is not None
        return self.path

    def write(self, ts: float, ip: str, size: int, inbound: bool) -> None:
        """N'accepte que des métadonnées (pas de bytes) : rien d'autre ne peut fuiter."""
        if self._writer is None:
            return
        self._writer.writerow(
            (f"{ts:.6f}", str(ip), int(size), "entrant" if inbound else "sortant")
        )
        self.count += 1

    def stop(self) -> None:
        if self._file is not None:
            self._file.close()
        self._file = None
        self._writer = None
