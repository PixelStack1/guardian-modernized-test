"""Lot 4 — « boîte noire » : enregistrement des dernières secondes.

Tampon circulaire EN MÉMOIRE de MÉTADONNÉES de paquets uniquement (horodatage,
IP/ports source et destination, protocole, taille, sens, verdict passe/jeté et
raison). Le contenu (payload) n'est JAMAIS conservé : ``PacketMeta`` n'a aucun
champ ``bytes``.

Sur déclencheur (touche [K] de la vue en direct, bouclier auto, récidiviste,
verrou de session), les ``seconds`` secondes AVANT et APRÈS le déclencheur sont
écrites dans ``%LOCALAPPDATA%\\Guardian\\enregistrements\\kick-AAAAMMJJ-HHMMSS-<motif>.csv``.
Les 4 premières colonnes sont celles de network/recorder.py, donc le fichier se
rejoue tel quel avec ``python -m guardian.replay <csv>`` ; les colonnes suivantes
ajoutent le détail. IP complètes, non masquées (choix de l'utilisateur).

Bornes : ``max_entries`` lignes en mémoire (200 000 par défaut, les plus anciennes
sont oubliées), ``max_files`` fichiers sur disque (20, les plus anciens supprimés).
Écriture atomique (fichier temporaire + ``os.replace``) dans un fil dédié.

Ce module est alimenté côté affichage (fil de la session en fond), JAMAIS dans la
boucle WinDivert : aucune erreur ici ne peut bloquer ni modifier le flux de
paquets. Toutes les méthodes publiques avalent leurs exceptions.
"""

from __future__ import annotations

import contextlib
import csv
import logging
import os
import queue
import re
import tempfile
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, NamedTuple

from network.recorder import HEADER

logger = logging.getLogger(__name__)

EXTRA_HEADER = (
    "ip_src",
    "port_src",
    "ip_dst",
    "port_dst",
    "proto",
    "verdict",
    "raison",
)
FULL_HEADER = HEADER + EXTRA_HEADER

DEFAULT_SECONDS = 30
MIN_SECONDS = 1
MAX_SECONDS = 300
MAX_ENTRIES = 200_000
MAX_FILES = 20
MAX_PENDING = 8
# Un même motif automatique ne déclenche pas plus d'une capture par période.
AUTO_COOLDOWN = 60.0
STALE_TMP_SECONDS = 60.0
CONFIG_KEY = "recording_seconds"
PREFIX = "kick-"

# Raisons de rejet (colonne « raison »).
R_PASS = ""
R_RELAY = "relais"
R_BLOCKED = "bloque"
R_TOTAL = "coupure_sortante"
R_PANIC = "panique"
R_OFFENDER = "recidiviste"
R_LOCK = "verrou"
R_UNKNOWN = "inconnue"

# Motifs de déclenchement (nom de fichier).
T_MANUAL = "manuel"
T_AUTO = "bouclier"
T_OFFENDER = "recidiviste"
T_LOCK = "verrou"


class PacketMeta(NamedTuple):
    """Métadonnées d'UN paquet. Aucun champ pour le contenu, par construction."""

    ts: float
    src: str
    sport: int
    dst: str
    dport: int
    proto: str
    size: int
    inbound: bool
    passed: bool
    reason: str = R_PASS

    @property
    def peer(self) -> str:
        return self.src if self.inbound else self.dst

    def row(self) -> tuple[str, ...]:
        return (
            f"{self.ts:.6f}",
            self.peer,
            str(int(self.size)),
            "entrant" if self.inbound else "sortant",
            self.src,
            str(int(self.sport)),
            self.dst,
            str(int(self.dport)),
            self.proto,
            "passe" if self.passed else "jete",
            self.reason,
        )


def clamp_seconds(raw: object) -> int:
    """``recording_seconds`` de data.json validé (entier borné, défaut 30)."""
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        return DEFAULT_SECONDS
    try:
        value = int(raw)
    except (ValueError, OverflowError):
        return DEFAULT_SECONDS
    return max(MIN_SECONDS, min(MAX_SECONDS, value))


def drop_reason(
    inbound: bool,
    peer: str,
    blocked: Any,
    total: Any,
    now: float,
    total_on: bool,
    relay_drop: bool,
    policy: Any,
) -> str:
    """Raison probable d'un rejet DÉJÀ décidé (appelée seulement si jeté).
    Lecture seule : ne modifie ni ``policy`` ni les listes. Erreur = « inconnue »."""
    try:
        if relay_drop:
            return R_RELAY
        if inbound:
            exp = blocked.get(peer)
            if exp is not None and (exp == 0.0 or now < exp):
                return R_BLOCKED
            if policy is not None:
                if policy.panic:
                    return R_PANIC
                if policy.offender_drop and peer in policy.offenders:
                    return R_OFFENDER
                if policy.lock_on and peer not in policy.seen:
                    return R_LOCK
            return R_UNKNOWN
        if total_on and peer in total:
            return R_TOTAL
        return R_UNKNOWN
    except Exception:
        return R_UNKNOWN


def meta_from_packet(packet: Any, now: float, sent: bool, reason: str) -> PacketMeta:
    """Extrait les métadonnées (jamais ``packet.payload`` lui-même, seulement sa
    longueur). Peut lever : l'appelant entoure d'un ``suppress``."""
    proto = (
        "udp"
        if getattr(packet, "udp", None) is not None
        else ("tcp" if getattr(packet, "tcp", None) is not None else "autre")
    )
    return PacketMeta(
        float(now),
        str(packet.ip.src_addr),
        int(packet.src_port or 0),
        str(packet.ip.dst_addr),
        int(packet.dst_port or 0),
        proto,
        len(packet.payload or b""),
        bool(packet.is_inbound),
        bool(sent),
        "" if sent else reason,
    )


def safe_label(label: str) -> str:
    return re.sub(r"[^a-z0-9_]", "", label.lower())[:20] or "kick"


class BlackBox:
    """Tampon circulaire borné + captures en attente (fenêtre avant/après)."""

    def __init__(
        self,
        directory: Path | Callable[[], Path] | None = None,
        seconds: int = DEFAULT_SECONDS,
        max_entries: int = MAX_ENTRIES,
        max_files: int = MAX_FILES,
        threaded: bool = True,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._directory = directory
        self.seconds = clamp_seconds(seconds)
        self.max_files = max(1, int(max_files))
        self.buffer: deque[PacketMeta] = deque(maxlen=max(1, int(max_entries)))
        self.pending: list[tuple[float, str]] = []
        self.last_auto: dict[str, float] = {}
        self.written: list[Path] = []
        self.errors = 0
        self.clock = clock
        self.threaded = threaded
        self._lock = threading.Lock()
        self._jobs: queue.Queue[tuple[float, str, list[PacketMeta]] | None] = (
            queue.Queue(MAX_PENDING)
        )
        self._thread: threading.Thread | None = None

    # -- alimentation ---------------------------------------------------------
    def add(self, meta: PacketMeta) -> None:
        if not isinstance(meta, PacketMeta):
            return  # rien d'autre que des métadonnées n'entre dans le tampon
        try:
            with self._lock:
                self.buffer.append(meta)
            self.tick(meta.ts)
        except Exception:
            self.errors += 1

    def trigger(self, label: str, now: float | None = None, auto: bool = False) -> bool:
        """Programme une capture [now - s, now + s]. True si programmée."""
        try:
            now = self.clock() if now is None else now
            label = safe_label(label)
            with self._lock:
                if auto:
                    last = self.last_auto.get(label)
                    if last is not None and now - last < AUTO_COOLDOWN:
                        return False
                    self.last_auto[label] = now
                # Une capture déjà en attente couvre ce déclencheur.
                if any(abs(now - ts) < self.seconds for ts, _l in self.pending):
                    return False
                if len(self.pending) >= MAX_PENDING:
                    return False
                self.pending.append((now, label))
            return True
        except Exception:
            self.errors += 1
            return False

    def tick(self, now: float | None = None) -> None:
        """Lance l'écriture des captures dont la fenêtre « après » est écoulée."""
        try:
            now = self.clock() if now is None else now
            with self._lock:
                due = [p for p in self.pending if now >= p[0] + self.seconds]
                if not due:
                    return
                self.pending = [p for p in self.pending if p not in due]
                jobs = [(ts, lbl, self._window(ts)) for ts, lbl in due]
            for job in jobs:
                self._submit(job)
        except Exception:
            self.errors += 1

    def flush(self) -> None:
        """Arrêt : écrit les captures en attente avec ce qui est disponible."""
        try:
            with self._lock:
                jobs = [(ts, lbl, self._window(ts)) for ts, lbl in self.pending]
                self.pending = []
            for job in jobs:
                self._submit(job)
            if self._thread is not None:
                with contextlib.suppress(queue.Full):
                    self._jobs.put(None, timeout=1)
                self._thread.join(timeout=5)
                self._thread = None
        except Exception:
            self.errors += 1

    def _window(self, ts: float) -> list[PacketMeta]:
        lo, hi = ts - self.seconds, ts + self.seconds
        return [m for m in self.buffer if lo <= m.ts <= hi]

    # -- écriture -------------------------------------------------------------
    def directory(self) -> Path:
        d = self._directory
        if d is None:
            from network.recorder import recordings_dir

            return recordings_dir()
        path = d() if callable(d) else d
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _submit(self, job: tuple[float, str, list[PacketMeta]]) -> None:
        if not self.threaded:
            self._write(*job)
            return
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(
                target=self._worker, name="blackbox", daemon=True
            )
            self._thread.start()
        try:
            self._jobs.put_nowait(job)
        except queue.Full:
            self.errors += 1

    def _worker(self) -> None:
        while True:
            job = self._jobs.get()
            if job is None:
                return
            self._write(*job)

    def _write(self, ts: float, label: str, rows: Iterable[PacketMeta]) -> Path | None:
        try:
            directory = self.directory()
            stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(ts))
            path = directory / f"{PREFIX}{stamp}-{label}.csv"
            n = 2
            while path.exists():
                path = directory / f"{PREFIX}{stamp}-{label}-{n}.csv"
                n += 1
            fd, tmp = tempfile.mkstemp(prefix=".tmp-", suffix=".csv", dir=directory)
            try:
                with os.fdopen(fd, "w", newline="", encoding="utf-8") as fh:
                    writer = csv.writer(fh)
                    writer.writerow(FULL_HEADER)
                    for meta in rows:
                        writer.writerow(meta.row())
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise
            self.written.append(path)
            del self.written[: -self.max_files]
            rotate(directory, self.max_files)
            return path
        except Exception:
            self.errors += 1
            logger.debug("boîte noire : écriture impossible", exc_info=True)
            return None


def rotate(directory: Path, max_files: int) -> list[Path]:
    """Garde les ``max_files`` captures les plus récentes ; renvoie les supprimées."""
    files = sorted(
        directory.glob(f"{PREFIX}*.csv"), key=lambda p: (p.stat().st_mtime, p.name)
    )
    removed = files[: max(0, len(files) - max_files)]
    # Lot 3 (F5) : restes .tmp-*.csv d'une écriture interrompue (plus vieux que
    # STALE_TMP_SECONDS, pour ne jamais toucher une écriture en cours).
    limit = time.time() - STALE_TMP_SECONDS
    for tmp in directory.glob(".tmp-*.csv"):
        with contextlib.suppress(OSError):
            if tmp.stat().st_mtime < limit:
                tmp.unlink()
    for path in removed:
        with contextlib.suppress(OSError):
            path.unlink()
    return removed
