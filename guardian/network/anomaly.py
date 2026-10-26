"""Statistiques par IP et détection d'anomalies pour la vue « Session en direct ».

Module pur (aucune dépendance à pydivert ni à la console) afin d'être testé
unitairement. Seules des métadonnées sont utilisées : IP, taille du paquet,
horodatage. Le contenu des paquets n'est jamais lu.

VERSION DE TEST : les seuils ci-dessous sont provisoires et seront ajustés à
partir d'enregistrements réels (mode enregistrement, voir network/recorder.py).
"""

from __future__ import annotations

import statistics
from collections import deque
from dataclasses import dataclass, field
from enum import IntEnum

from util.i18n import t

# ---------------------------------------------------------------------------
# Seuils réglables (à ajuster d'après les enregistrements réels)
# ---------------------------------------------------------------------------

# Largeur de la fenêtre glissante (secondes) pour paquets/s, octets/s, tailles.
WINDOW_SECONDS = 3.0

# Durée d'apprentissage de la « normale » d'un pair après sa première apparition.
# Pendant ce temps, aucune rafale n'est signalée pour ce pair.
BASELINE_SECONDS = 60.0

# Plancher du débit de référence (paquets/s) : évite qu'un pair très calme
# (ex. 1 paquet/s) soit signalé dès 5 paquets/s.
BASELINE_MIN_PPS = 10.0

# (a) Rafale : débit courant >= BURST_RATIO x débit de référence -> orange.
BURST_RATIO = 5.0
# Rafale forte : débit courant >= BURST_RATIO_SEVERE x référence -> rouge direct.
BURST_RATIO_SEVERE = 10.0
# Débit absolu minimal pour parler de rafale (ignore les petits pics).
BURST_MIN_PPS = 100.0

# (b) Tailles anormales.
# Paquet « énorme » : taille > HUGE_FACTOR x la plus grande taille vue chez les
# autres pairs ET > HUGE_MIN_BYTES.
HUGE_FACTOR = 1.5
HUGE_MIN_BYTES = 1200
# Série de petits paquets identiques : TINY_RUN_LENGTH paquets consécutifs de
# même taille <= TINY_MAX_BYTES (hors tailles de heartbeat connues).
TINY_MAX_BYTES = 32
TINY_RUN_LENGTH = 200
# Tailles ignorées pour la série de petits paquets (heartbeats R*, cf. sessions.py).
TINY_IGNORED_SIZES = frozenset({12, 18})

# (c) Ciblé : la rafale ne concerne que ce pair. Si au moins
# SESSION_WIDE_FRACTION des autres pairs (au moins 2) sont aussi en rafale,
# c'est probablement un événement de jeu (chargement, cinématique) : pas d'alerte.
SESSION_WIDE_FRACTION = 0.5

# Passage orange -> rouge si l'anomalie dure au moins ce nombre de secondes.
SUSPECT_PERSIST_SECONDS = 5.0
# Retour à la normale après ce nombre de secondes sans anomalie.
CALM_SECONDS = 10.0

# Un pair est « connecté » s'il a envoyé un paquet dans ce délai (cf. ConnectionStats).
CONNECTED_SECONDS = 5.0


class Level(IntEnum):
    NORMAL = 0
    INHABITUEL = 1  # orange
    SUSPECT = 2  # rouge


LEVEL_KEYS = {
    Level.NORMAL: "level.normal",
    Level.INHABITUEL: "level.inhabituel",
    Level.SUSPECT: "level.suspect",
}


@dataclass
class WindowStats:
    pps: float
    bps: float
    avg_size: float
    max_size: int


class SlidingWindow:
    """Fenêtre glissante de (horodatage, taille) sur ``seconds`` secondes."""

    def __init__(self, seconds: float = WINDOW_SECONDS) -> None:
        if seconds <= 0:
            raise ValueError("seconds doit être > 0")
        self.seconds = seconds
        self._items: deque[tuple[float, int]] = deque()
        self._bytes = 0

    def add(self, ts: float, size: int) -> None:
        self._items.append((ts, size))
        self._bytes += size
        self.expire(ts)

    def expire(self, now: float) -> None:
        limit = now - self.seconds
        while self._items and self._items[0][0] <= limit:
            self._bytes -= self._items.popleft()[1]

    def stats(self, now: float) -> WindowStats:
        self.expire(now)
        count = len(self._items)
        if count == 0:
            return WindowStats(0.0, 0.0, 0.0, 0)
        return WindowStats(
            pps=count / self.seconds,
            bps=self._bytes / self.seconds,
            avg_size=self._bytes / count,
            max_size=max(size for _, size in self._items),
        )


@dataclass
class PeerState:
    ip: str
    first_seen: float
    last_seen: float
    window: SlidingWindow = field(default_factory=SlidingWindow)
    # Comptage par seconde pendant l'apprentissage (médiane = robuste aux pics).
    learning_buckets: dict[int, int] = field(default_factory=dict)
    baseline_pps: float | None = None
    max_size_ever: int = 0
    tiny_run_size: int = -1
    tiny_run_length: int = 0
    level: Level = Level.NORMAL
    anomaly_since: float | None = None
    last_anomaly: float | None = None
    alert: str = ""
    # Clé de traduction de la cause principale (« reason.burst », ...).
    reason_key: str = ""

    def learning(self, now: float) -> bool:
        return now - self.first_seen < BASELINE_SECONDS


class SessionMonitor:
    """Suit tous les pairs et calcule leur niveau d'anomalie."""

    def __init__(self) -> None:
        self.peers: dict[str, PeerState] = {}

    # -- alimentation ----------------------------------------------------
    def add_packet(self, ip: str, size: int, ts: float) -> None:
        """Paquet ENTRANT reçu de ``ip`` (taille de la charge utile en octets)."""
        size = max(0, int(size))
        peer = self.peers.get(ip)
        if peer is None:
            peer = PeerState(ip=ip, first_seen=ts, last_seen=ts)
            self.peers[ip] = peer
        peer.last_seen = max(peer.last_seen, ts)
        peer.window.add(ts, size)
        peer.max_size_ever = max(peer.max_size_ever, size)
        if peer.learning(ts):
            bucket = int(ts - peer.first_seen)
            peer.learning_buckets[bucket] = peer.learning_buckets.get(bucket, 0) + 1
        elif peer.baseline_pps is None:
            self._finish_learning(peer)
        if size <= TINY_MAX_BYTES and size not in TINY_IGNORED_SIZES:
            if size == peer.tiny_run_size:
                peer.tiny_run_length += 1
            else:
                peer.tiny_run_size, peer.tiny_run_length = size, 1
        else:
            peer.tiny_run_size, peer.tiny_run_length = -1, 0

    @staticmethod
    def _finish_learning(peer: PeerState) -> None:
        # Médiane des paquets/s sur toutes les secondes d'apprentissage (0 inclus).
        n = max(1, int(BASELINE_SECONDS))
        counts = [peer.learning_buckets.get(i, 0) for i in range(n)]
        peer.baseline_pps = float(statistics.median(counts))
        peer.learning_buckets.clear()

    # -- lecture ---------------------------------------------------------
    def connected(self, now: float) -> list[PeerState]:
        return [
            p for p in self.peers.values() if now - p.last_seen <= CONNECTED_SECONDS
        ]

    def forget(self, ip: str) -> None:
        self.peers.pop(ip, None)

    def prune(self, now: float, idle_seconds: float = 60.0) -> None:
        for ip in [
            ip for ip, p in self.peers.items() if now - p.last_seen > idle_seconds
        ]:
            del self.peers[ip]

    def _is_bursting(self, peer: PeerState, stats: WindowStats, now: float) -> float:
        """Renvoie le ratio débit/référence si rafale, sinon 0."""
        if peer.learning(now):
            return 0.0
        if peer.baseline_pps is None:
            self._finish_learning(peer)
        assert peer.baseline_pps is not None
        ref = max(peer.baseline_pps, BASELINE_MIN_PPS)
        ratio = stats.pps / ref
        if stats.pps >= BURST_MIN_PPS and ratio >= BURST_RATIO:
            return ratio
        return 0.0

    def evaluate(self, now: float) -> list[PeerState]:
        """Met à jour niveau et message d'alerte de chaque pair connecté."""
        peers = self.connected(now)
        stats = {p.ip: p.window.stats(now) for p in peers}
        bursts = {p.ip: self._is_bursting(p, stats[p.ip], now) for p in peers}
        for peer in peers:
            s = stats[peer.ip]
            others = [o for o in peers if o.ip != peer.ip]
            reasons: list[str] = []
            keys: list[str] = []
            severe = False

            ratio = bursts[peer.ip]
            if ratio:
                bursting_others = sum(1 for o in others if bursts[o.ip])
                session_wide = (
                    bursting_others >= 2
                    and bursting_others >= SESSION_WIDE_FRACTION * len(others)
                )
                if not session_wide:
                    assert peer.baseline_pps is not None
                    reasons.append(
                        t("anomaly.burst", pps=s.pps, base=peer.baseline_pps)
                        + (t("anomaly.targeted") if others else "")
                    )
                    keys.append("reason.burst")
                    severe = ratio >= BURST_RATIO_SEVERE

            others_max = max((o.max_size_ever for o in others), default=0)
            if (
                others_max
                and s.max_size > HUGE_MIN_BYTES
                and s.max_size > HUGE_FACTOR * others_max
            ):
                reasons.append(t("anomaly.huge", size=s.max_size, others=others_max))
                keys.append("reason.huge")

            if peer.tiny_run_length >= TINY_RUN_LENGTH:
                reasons.append(
                    t(
                        "anomaly.tiny",
                        count=peer.tiny_run_length,
                        size=peer.tiny_run_size,
                    )
                )
                keys.append("reason.tiny")

            if keys:
                peer.reason_key = keys[0]
            self._update_level(peer, reasons, severe, now)
        return peers

    @staticmethod
    def _update_level(
        peer: PeerState, reasons: list[str], severe: bool, now: float
    ) -> None:
        if reasons:
            if peer.anomaly_since is None:
                peer.anomaly_since = now
            peer.last_anomaly = now
            persisted = now - peer.anomaly_since >= SUSPECT_PERSIST_SECONDS
            new_level = (
                Level.SUSPECT
                if severe or persisted or len(reasons) >= 2
                else Level.INHABITUEL
            )
            peer.level = max(peer.level, new_level)
            peer.alert = f"IP {peer.ip} : " + " ; ".join(reasons)
        elif peer.last_anomaly is None or now - peer.last_anomaly >= CALM_SECONDS:
            peer.level = Level.NORMAL
            peer.anomaly_since = None
            peer.last_anomaly = None
            peer.alert = ""
            peer.reason_key = ""
