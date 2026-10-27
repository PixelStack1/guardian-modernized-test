"""Statistiques par IP et détection d'anomalies pour la vue « Session en direct ».

Module pur (aucune dépendance à pydivert ni à la console) afin d'être testé
unitairement. Seules des métadonnées sont utilisées : IP, taille du paquet,
horodatage. Le contenu des paquets n'est jamais lu.

VERSION DE TEST : les seuils ci-dessous sont provisoires et seront ajustés à
partir d'enregistrements réels (mode enregistrement, voir network/recorder.py).
"""

from __future__ import annotations

import math
import statistics
from bisect import bisect_right
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

# Nombre maximal de pairs suivis : borne le coût CPU/mémoire si un flot d'IP
# sources usurpées arrive. Au-delà, le pair le plus ancien (inactif) est oublié,
# et si tous sont actifs, les nouvelles IP sont ignorées par la vue.
MAX_PEERS = 512
# Nombre maximal de ports sources mémorisés par pair (rapport d'incident).
MAX_PORTS_PER_PEER = 16

# Règle absolue du bouclier (valeur validée par l'utilisateur) : une IP qui
# soutient > SHIELD_PPS paquets/s (fenêtre glissante d'1 s) pendant SHIELD_SECONDS
# consécutives
# passe directement en rouge (« reason.rate »), même pendant l'apprentissage.
# S'ajoute à la règle x5 / 100 paquets/s ci-dessus. Réglable dans data.json.
SHIELD_PPS_KEY = "shield_pps"
SHIELD_PPS = 80
SHIELD_PPS_MIN, SHIELD_PPS_MAX = 20, 1000
SHIELD_SECONDS_KEY = "shield_seconds"
SHIELD_SECONDS = 5.0
SHIELD_SECONDS_MIN, SHIELD_SECONDS_MAX = 1.0, 60.0
# Borne mémoire des horodatages de la fenêtre d'1 s, par pair.
# Tolérance flottante sur les bornes de fenêtre / durée.
_EPS = 1e-6
# Bouclier absolu : mémoire fixe par IP, ratio par tranche, facteur d'inondation.
RATE_CAP = 8192
SLICE_RATIO = 0.75
FLOOD_FACTOR = 3
MIN_SLICES = 3
SATURATION_MIN_AGE = 1.0
COMPACT_AT = 1024


def _clamp(raw: object, default: float, lo: float, hi: float) -> float:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return default
    v = float(raw)
    if v != v or v in (float("inf"), float("-inf")):
        return default
    return max(lo, min(hi, v))


def clamp_shield_pps(raw: object) -> int:
    return int(_clamp(raw, SHIELD_PPS, SHIELD_PPS_MIN, SHIELD_PPS_MAX))


def clamp_shield_seconds(raw: object) -> float:
    return _clamp(raw, SHIELD_SECONDS, SHIELD_SECONDS_MIN, SHIELD_SECONDS_MAX)


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


class TimeWindow:
    """Horodatages croissants avec purge incrémentale par la gauche et comptage
    par bisect (O(log n)). Mémoire bornée par ``cap``."""

    __slots__ = ("_ts", "_head", "_cap")

    def __init__(self) -> None:
        self._ts: list[float] = []
        self._head = 0
        self._cap = 1 << 62

    def __len__(self) -> int:
        return len(self._ts) - self._head

    def add(self, ts: float, older_than: float, cap: int) -> None:
        if self._ts and ts < self._ts[-1]:
            ts = self._ts[-1]  # horloge non monotone : on garde l'ordre
        self._ts.append(ts)
        self._cap = cap
        self._head = max(
            bisect_right(self._ts, older_than, self._head), len(self._ts) - cap
        )
        # R1 : compactage dès 1024 éléments morts -> stockage <= cap + 1024.
        if self._head >= COMPACT_AT:
            del self._ts[: self._head]
            self._head = 0

    def prune(self, older_than: float) -> None:
        """Oublie les éléments <= ``older_than`` (fenêtre raccourcie)."""
        self._head = bisect_right(self._ts, older_than, self._head)
        if self._head >= COMPACT_AT:
            del self._ts[: self._head]
            self._head = 0

    @property
    def last(self) -> float:
        return self._ts[-1] if len(self) else float("-inf")

    def saturated(self, span: float) -> bool:
        """Plafond atteint alors que les éléments couvrent moins de ``span``."""
        return len(self) >= self._cap and self._ts[-1] - self._ts[self._head] < span

    def count(self, lo: float, hi: float) -> int:
        """Éléments dans (lo, hi]."""
        hi_i: int = bisect_right(self._ts, hi, self._head)
        return hi_i - bisect_right(self._ts, lo, self._head)


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

    def snapshot(self, limit: int = 20) -> list[tuple[float, int]]:
        """Derniers (horodatage, taille) de la fenêtre (extrait pour les rapports)."""
        items = list(self._items)
        return items[-limit:] if limit > 0 else []

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
    # Totaux et pic, pour les rapports d'incident.
    total_packets: int = 0
    total_bytes: int = 0
    peak_pps: float = 0.0
    ports: set[int] = field(default_factory=set)
    # Règle absolue : horodatages de la dernière seconde et début de la période
    # où le débit d'1 s est resté >= shield_pps (None = sous le seuil).
    rate_ts: TimeWindow = field(default_factory=lambda: TimeWindow())

    def learning(self, now: float) -> bool:
        return now - self.first_seen < BASELINE_SECONDS


class SessionMonitor:
    """Suit tous les pairs et calcule leur niveau d'anomalie."""

    def __init__(
        self, shield_pps: object = SHIELD_PPS, shield_seconds: object = SHIELD_SECONDS
    ) -> None:
        self.peers: dict[str, PeerState] = {}
        # Borne mémoire : au-delà, la moyenne dépasse forcément tout seuil permis.
        self.rate_cap = RATE_CAP
        self.set_shield(shield_pps, shield_seconds)

    def set_shield(self, shield_pps: object, shield_seconds: object) -> None:
        """Change le seuil et le délai du bouclier en gardant l'état cohérent.

        Reborne les deux valeurs, recalcule le nombre de tranches d'1 s et la
        rétention. Si la rétention raccourcit, les horodatages trop anciens sont
        oubliés tout de suite ; si elle s'allonge, l'historique déjà conservé reste
        valide (il couvre simplement moins que la nouvelle fenêtre au début)."""
        self.shield_pps = clamp_shield_pps(shield_pps)
        self.shield_seconds = clamp_shield_seconds(shield_seconds)
        self.slices = max(MIN_SLICES, math.ceil(self.shield_seconds - _EPS))
        # Horodatages conservés : fenêtre de moyenne ET tranches d'1 s.
        self.retention = max(self.shield_seconds, float(self.slices))
        for peer in self.peers.values():
            last = peer.rate_ts.last
            if last != float("-inf"):
                peer.rate_ts.prune(last - self.retention + _EPS)

    # -- alimentation ----------------------------------------------------
    def add_packet(
        self, ip: str, size: int, ts: float, port: int | None = None
    ) -> None:
        """Paquet ENTRANT reçu de ``ip`` (taille de la charge utile en octets)."""
        size = max(0, int(size))
        peer = self.peers.get(ip)
        if peer is None:
            if len(self.peers) >= MAX_PEERS and not self._make_room(ts):
                return
            peer = PeerState(ip=ip, first_seen=ts, last_seen=ts)
            self.peers[ip] = peer
        peer.last_seen = max(peer.last_seen, ts)
        peer.total_packets += 1
        peer.total_bytes += size
        if port is not None and len(peer.ports) < MAX_PORTS_PER_PEER:
            peer.ports.add(int(port))
        peer.window.add(ts, size)
        self._track_rate(peer, ts)
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

    def _track_rate(self, peer: PeerState, ts: float) -> None:
        peer.rate_ts.add(ts, ts - self.retention + _EPS, self.rate_cap)

    def _count(self, peer: PeerState, lo: float, hi: float) -> int:
        """Paquets sur (lo, hi], en O(log n) (bisect)."""
        return peer.rate_ts.count(lo + _EPS, hi + _EPS)

    def window_count(self, peer: PeerState, now: float) -> int:
        """Paquets sur (now - shield_seconds, now]."""
        return self._count(peer, now - self.shield_seconds, now)

    def rate(self, peer: PeerState, now: float) -> int:
        """Débit moyen réel (paquets/s) sur les shield_seconds dernières secondes."""
        return round(self.window_count(peer, now) / self.shield_seconds)

    def sustained(self, peer: PeerState, now: float) -> bool:
        """Dépassement soutenu à ``now`` si l'une des règles suivantes est vraie :

        1. Saturation (F1/F4) : la mémoire bornée (RATE_CAP horodatages) est pleine
           alors qu'elle couvre moins que la période retenue, le dernier paquet a
           moins d'1 s, et l'IP est vue depuis au moins SATURATION_MIN_AGE (1 s).
           Choix : pas d'exigence d'ancienneté shield_seconds ici, car remplir
           8192 horodatages en < shield_seconds suppose déjà > 1600 paquets/s en
           moyenne (défaut 5 s) ; un pic de 2 s sous 4096 paquets/s ne sature pas.
        2. Inondation (F3) : plus de 3 × shield_pps × shield_seconds paquets sur la
           fenêtre, quel que soit le nombre de tranches ou l'ancienneté.
        3. Règle normale : IP vue depuis au moins shield_seconds, plus de
           shield_pps × shield_seconds paquets sur la fenêtre, et au moins N-1 des
           N dernières tranches d'1 s (N = ceil(shield_seconds), minimum 3) avec
           chacune plus de 75 % de shield_pps (F2/F5)."""
        q = peer.rate_ts
        if (
            q.saturated(self.retention)
            and now - q.last < 1.0
            and now - peer.first_seen >= SATURATION_MIN_AGE - _EPS
        ):
            return True
        count = self.window_count(peer, now)
        budget = self.shield_pps * self.shield_seconds
        if count > FLOOD_FACTOR * budget + _EPS:
            return True
        if now - peer.first_seen < self.shield_seconds - _EPS or count <= budget + _EPS:
            return False
        busy = sum(
            1
            for k in range(self.slices)
            if self._count(peer, now - k - 1, now - k) > SLICE_RATIO * self.shield_pps
        )
        return busy >= self.slices - 1

    def _make_room(self, now: float) -> bool:
        """Libère une place en oubliant le pair vu le moins récemment s'il est inactif."""
        oldest = min(self.peers.values(), key=lambda p: p.last_seen)
        if now - oldest.last_seen <= CONNECTED_SECONDS:
            return False
        del self.peers[oldest.ip]
        return True

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
        baseline = peer.baseline_pps if peer.baseline_pps is not None else 0.0
        ref = max(baseline, BASELINE_MIN_PPS)
        ratio = stats.pps / ref
        if stats.pps >= BURST_MIN_PPS and ratio >= BURST_RATIO:
            return ratio
        return 0.0

    def evaluate(self, now: float) -> list[PeerState]:
        """Met à jour niveau et message d'alerte de chaque pair connecté."""
        peers = self.connected(now)
        stats = {p.ip: p.window.stats(now) for p in peers}
        bursts = {p.ip: self._is_bursting(p, stats[p.ip], now) for p in peers}
        # Calculés une seule fois par évaluation (coût O(n) au lieu de O(n²)).
        total_bursting = sum(1 for r in bursts.values() if r)
        # Deux plus grandes tailles vues : le max « des autres » d'un pair est la
        # 2e si ce pair détient la 1re, sinon la 1re.
        top: list[tuple[int, str]] = sorted(
            ((p.max_size_ever, p.ip) for p in peers), reverse=True
        )[:2]
        n_others = len(peers) - 1
        for peer in peers:
            s = stats[peer.ip]
            peer.peak_pps = max(peer.peak_pps, s.pps)
            reasons: list[str] = []
            keys: list[str] = []
            severe = False

            ratio = bursts[peer.ip]
            if ratio:
                bursting_others = total_bursting - 1
                session_wide = (
                    bursting_others >= 2
                    and bursting_others >= SESSION_WIDE_FRACTION * n_others
                )
                if not session_wide:
                    reasons.append(
                        t("anomaly.burst", pps=s.pps, base=peer.baseline_pps or 0.0)
                        + (t("anomaly.targeted") if n_others > 0 else "")
                    )
                    keys.append("reason.burst")
                    severe = ratio >= BURST_RATIO_SEVERE

            if self.sustained(peer, now):
                reasons.insert(
                    0,
                    t(
                        "anomaly.rate",
                        pps=self.rate(peer, now),
                        max=self.shield_pps,
                        seconds=self.shield_seconds,
                    ),
                )
                keys.insert(0, "reason.rate")
                severe = True

            if not top:
                others_max = 0
            elif top[0][1] != peer.ip:
                others_max = top[0][0]
            else:
                others_max = top[1][0] if len(top) > 1 else 0
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
