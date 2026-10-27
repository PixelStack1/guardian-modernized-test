"""Lot 3 — filtres d'information : pays, ping estimé, débit par joueur, badge VPN.

Côté AFFICHAGE uniquement (jamais dans la boucle de capture) : métadonnées
(horodatage, ip, taille, sens), aucun contenu de paquet, aucun appel réseau.
Ces filtres SIGNALENT ; seul le badge VPN peut demander un blocage, et
seulement si ``vpn_auto_block`` est activé (désactivé par défaut). Le
contrôleur garde la décision finale (amis, Rockstar, pays de confiance : jamais).
Toute erreur = rien n'est signalé (le paquet est déjà passé).
"""

from __future__ import annotations

import contextlib
import math
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from statistics import median
from typing import Any

from util.geoip import country_code
from util.vpn import is_vpn

# Clés de data.json et valeurs par défaut.
TRUSTED_KEY = "trusted_countries"
TRUSTED_DEFAULT: tuple[str, ...] = ("FR", "BE", "CH", "CA")
PING_KEY = "ping_max_ms"
PING_DEFAULT = 150.0
RATE_KEY = "rate_limit_pps"
RATE_DEFAULT = 60
VPN_FLAG_KEY = "vpn_flag"
VPN_FLAG_DEFAULT = True
VPN_BLOCK_KEY = "vpn_auto_block"
VPN_BLOCK_DEFAULT = False

# Ping passif : un échantillon = délai entre NOTRE premier paquet sortant après un
# silence du pair (>= PING_IDLE s) et sa première réponse entrante. Bornes.
PING_IDLE = 0.2
PING_MAX_SAMPLE = 2.0
PING_SAMPLES = 16
PING_MIN_SAMPLES = 5
# Bornes mémoire (IP suivies).
MAX_TRACKED = 1024
# Une alerte par IP et par motif, au plus toutes les ALERT_COOLDOWN s.
ALERT_COOLDOWN = 60.0


def _finite(value: object, default: float, lo: float, hi: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    v = float(value)
    if not math.isfinite(v) or not lo <= v <= hi:
        return default
    return v


@dataclass
class FilterSettings:
    trusted: frozenset[str] = frozenset(TRUSTED_DEFAULT)
    ping_max_ms: float = PING_DEFAULT
    rate_pps: int = RATE_DEFAULT
    vpn_flag: bool = VPN_FLAG_DEFAULT
    vpn_auto_block: bool = VPN_BLOCK_DEFAULT

    @classmethod
    def from_config(cls, data: Mapping[str, Any] | None) -> FilterSettings:
        """Réglages validés de data.json ; valeur invalide = défaut."""
        data = data if isinstance(data, Mapping) else {}
        trusted = set(TRUSTED_DEFAULT)
        raw = data.get(TRUSTED_KEY)
        if isinstance(raw, list):
            trusted |= {
                c.upper()
                for c in raw
                if isinstance(c, str) and len(c) == 2 and c.isascii() and c.isalpha()
            }
        vpn_flag = data.get(VPN_FLAG_KEY, VPN_FLAG_DEFAULT)
        vpn_block = data.get(VPN_BLOCK_KEY, VPN_BLOCK_DEFAULT)
        return cls(
            trusted=frozenset(trusted),
            ping_max_ms=_finite(data.get(PING_KEY), PING_DEFAULT, 1.0, 10_000.0),
            rate_pps=int(_finite(data.get(RATE_KEY), RATE_DEFAULT, 1.0, 100_000.0)),
            vpn_flag=vpn_flag if isinstance(vpn_flag, bool) else VPN_FLAG_DEFAULT,
            vpn_auto_block=vpn_block if isinstance(vpn_block, bool) else False,
        )


class PingEstimator:
    """RTT ESTIMÉ, best-effort, à partir des horodatages seuls (voir module).

    Limites : le jeu est en UDP pair-à-pair continu, sans paire requête/réponse
    visible ; l'échantillon mesure « notre paquet -> prochain paquet du pair »,
    qui inclut le délai de traitement/tick du pair. C'est une indication, jamais
    une mesure : utilisé UNIQUEMENT pour signaler."""

    def __init__(self, max_tracked: int = MAX_TRACKED) -> None:
        self.max_tracked = max_tracked
        self.last_in: dict[str, float] = {}
        self.pending: dict[str, float] = {}
        self.samples: dict[str, deque[float]] = {}

    def observe(self, ts: float, ip: str, inbound: bool) -> None:
        if inbound:
            sent = self.pending.pop(ip, None)
            if sent is not None and 0.0 <= ts - sent <= PING_MAX_SAMPLE:
                if ip not in self.samples:
                    if len(self.samples) >= self.max_tracked:
                        del self.samples[next(iter(self.samples))]
                    self.samples[ip] = deque(maxlen=PING_SAMPLES)
                self.samples[ip].append((ts - sent) * 1000.0)
            self.last_in.pop(ip, None)
            if len(self.last_in) >= self.max_tracked:
                del self.last_in[next(iter(self.last_in))]
            self.last_in[ip] = ts
            return
        last = self.last_in.get(ip)
        if ip in self.pending or last is None or ts - last < PING_IDLE:
            return
        if len(self.pending) >= self.max_tracked:
            del self.pending[next(iter(self.pending))]
        self.pending[ip] = ts

    def estimate(self, ip: str) -> float | None:
        """Médiane des échantillons (ms), ou None si pas assez d'échantillons."""
        s = self.samples.get(ip)
        if not s or len(s) < PING_MIN_SAMPLES:
            return None
        return float(median(s))


class RateMeter:
    """Paquets ENTRANTS par seconde et par IP (fenêtre glissante d'une seconde)."""

    def __init__(self, max_tracked: int = MAX_TRACKED) -> None:
        self.max_tracked = max_tracked
        self.windows: dict[str, deque[float]] = {}

    def observe(self, ts: float, ip: str, limit: int) -> int:
        w = self.windows.get(ip)
        if w is None:
            if len(self.windows) >= self.max_tracked:
                del self.windows[next(iter(self.windows))]
            w = self.windows[ip] = deque()
        w.append(ts)
        while w and ts - w[0] >= 1.0:
            w.popleft()
        # Borne mémoire : au-delà de 2x la limite on ne garde que l'utile.
        while len(w) > max(2 * limit, 1):
            w.popleft()
        return len(w)


@dataclass
class Flags:
    country: str | None = None
    foreign: bool = False
    vpn: bool = False
    ping_ms: float | None = None
    slow: bool = False
    pps: int = 0
    flood: bool = False


@dataclass
class PeerFilters:
    """Agrège les filtres du lot 3. ``alert(key, **kw)`` formate une ligne."""

    settings: FilterSettings = field(default_factory=FilterSettings)
    is_protected: Callable[[str], bool] = lambda _ip: False
    ping: PingEstimator = field(default_factory=PingEstimator)
    rate: RateMeter = field(default_factory=RateMeter)
    flags: dict[str, Flags] = field(default_factory=dict)
    alerted: dict[tuple[str, str], float] = field(default_factory=dict)

    def _cooldown_ok(self, ip: str, reason: str, ts: float) -> bool:
        """Délais indépendants par (IP, motif) ; exactement ALERT_COOLDOWN = accepté."""
        key = (ip, reason)
        last = self.alerted.get(key)
        if last is not None and ts - last < ALERT_COOLDOWN:
            return False
        if key not in self.alerted and len(self.alerted) >= 4 * MAX_TRACKED:
            self.alerted.clear()
        self.alerted[key] = ts
        return True

    def observe(
        self, ts: float, ip: str, inbound: bool
    ) -> list[tuple[str, dict[str, Any]]]:
        """Renvoie les alertes (clé i18n, paramètres). Jamais d'exception."""
        out: list[tuple[str, dict[str, Any]]] = []
        try:
            if self.is_protected(ip):
                return out
            self.ping.observe(ts, ip, inbound)
            if not inbound:
                return out
            f = self.flags.get(ip)
            if f is None:
                if len(self.flags) >= MAX_TRACKED:
                    del self.flags[next(iter(self.flags))]
                f = self.flags[ip] = Flags(country=country_code(ip))
                f.foreign = (
                    f.country is not None and f.country not in self.settings.trusted
                )
                f.vpn = self.settings.vpn_flag and is_vpn(ip)
                if f.foreign and self._cooldown_ok(ip, "pays", ts):
                    out.append(("live.ev.foreign", {"ip": ip, "cc": f.country}))
                if f.vpn and self._cooldown_ok(ip, "vpn", ts):
                    out.append(("live.ev.vpn", {"ip": ip}))
            f.pps = self.rate.observe(ts, ip, self.settings.rate_pps)
            f.flood = f.pps >= self.settings.rate_pps
            if f.flood and self._cooldown_ok(ip, "debit", ts):
                out.append(
                    (
                        "live.ev.rate",
                        {"ip": ip, "pps": f.pps, "max": self.settings.rate_pps},
                    )
                )
            f.ping_ms = self.ping.estimate(ip)
            f.slow = f.ping_ms is not None and f.ping_ms > self.settings.ping_max_ms
            if f.slow and self._cooldown_ok(ip, "ping", ts):
                out.append(
                    (
                        "live.ev.ping",
                        {
                            "ip": ip,
                            "ms": round(f.ping_ms or 0),
                            "max": round(self.settings.ping_max_ms),
                        },
                    )
                )
        except Exception:
            return []
        return out

    def badges(self, ip: str) -> str:
        """Badges courts pour le tableau (« VPN », « ≠FR »...), vide si rien."""
        with contextlib.suppress(Exception):
            f = self.flags.get(ip)
            if f is None:
                return ""
            parts = []
            if f.vpn:
                parts.append("VPN")
            if f.foreign:
                parts.append("PAYS")
            if f.flood:
                parts.append("DEBIT")
            if f.slow:
                parts.append("PING")
            return ",".join(parts)
        return ""

    def wants_vpn_block(self, ip: str) -> bool:
        """Demande de blocage VPN (le contrôleur applique ses garde-fous)."""
        f = self.flags.get(ip)
        return bool(self.settings.vpn_auto_block and f is not None and f.vpn)
