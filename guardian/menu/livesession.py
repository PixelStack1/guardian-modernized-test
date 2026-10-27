"""Vue « Session en direct » (VERSION DE TEST, non activée par défaut ailleurs).

Affiche un tableau des pairs connectés (paquets/s, octets/s, tailles), signale
les comportements inhabituels (orange) ou suspects (rouge), et permet de
bloquer une IP. Le blocage réutilise la Blacklist existante (data.json).

Principe : un processus de capture ouvre un handle WinDivert (même filtre strict
que les sessions) avec une priorité plus haute que les filtres de session. Il
rejette les paquets ENTRANTS des IP bloquées, réinjecte tout le reste tel quel
(les filtres de session éventuels s'appliquent ensuite) et n'envoie au processus
d'affichage que des métadonnées : (horodatage, ip, taille, entrant).
Aucune lecture/modification du jeu, aucun paquet émis vers qui que ce soit.
"""

from __future__ import annotations

import atexit
import contextlib
import logging
import queue
import re
import shutil
import sys
import time
from collections.abc import Callable, Collection, MutableMapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from multiprocessing import Manager, Process, Queue, Value
from typing import Any

from colorama import Fore, Style

from config.configdata import ConfigData
from config.globallist import Blacklist
from network.anomaly import LEVEL_KEYS, Level, PeerState, SessionMonitor
from network.relay import (
    RELAY_DEFAULT,
    RELAY_KEY,
    is_block,
    is_relay_traffic,
    normalize,
    toggled,
)
from util.geoip import country_code
from util.i18n import t
from util.sound import beep

# Priorité WinDivert du handle de la vue en direct (plus haute = vu en premier).
LIVE_PRIORITY = 1000
# Durée d'un blocage automatique (secondes) : 7 jours, persistant dans
# auto_block.json (séparé de data.json), levé avant terme avec la touche D.
AUTO_BLOCK_SECONDS = 7 * 24 * 3600
# Mode « blocage total » : durée de la coupure SORTANTE vers une IP bloquée
# (en mémoire, jamais persistée). Ensuite seul le blocage entrant continue.
TOTAL_BLOCK_SECONDS = 600
# Clé de data.json du mode blocage total (DÉSACTIVÉ si absente).
TOTAL_BLOCK_KEY = "total_block"
TOTAL_BLOCK_DEFAULT = False
# Clé de data.json du bouclier auto (IP rouges uniquement). ACTIVÉ si absente.
# Les IP orange ne sont jamais bloquées automatiquement (bouclier manuel).
AUTO_BLOCK_KEY = "auto_block_suspect"
# DÉSACTIVÉ par défaut pendant la phase de test (activable avec la touche A).
AUTO_BLOCK_DEFAULT = False
# Fréquence d'évaluation des anomalies / du bouclier auto (secondes).
EVAL_SECONDS = 0.1
# Rafraîchissement de la liste de blocage dans le processus de capture (secondes).
BLOCKLIST_REFRESH = 0.05
REFRESH_SECONDS = 1.0
QUEUE_MAX = 100_000

# Lot 2 — verrou de session : quand ACTIVÉ, toute IP jamais vue (en entrant) dans la
# session courante est jetée dès son premier paquet. Jamais les serveurs Rockstar.
SESSION_LOCK_KEY = "session_lock"
SESSION_LOCK_DEFAULT = False
# Nombre max d'IP mémorisées comme « déjà vues » par le processus de capture.
MAX_SEEN = 4096
# Lot 2 — récidivistes : réglages « alerte sonore » et « coupure immédiate ».
OFFENDER_SOUND_KEY = "offender_sound"
OFFENDER_SOUND_DEFAULT = True
OFFENDER_DROP_KEY = "offender_drop"
OFFENDER_DROP_DEFAULT = True
# Lot 2 — liste d'amis (data.json, ip -> pseudo) : toujours autorisés (verrou,
# bouclier auto, récidivistes, panique). Bouton panique : en mémoire seulement.
FRIENDS_KEY = "friends"
MAX_FRIENDS = 500
MAX_NICK = 32
# Raison enregistrée pour un blocage manuel (touche B).
MANUAL_REASON = "manual"
# Nombre max d'IP déjà signalées « récidiviste de retour » dans une session.
OFFENDER_ALERTED_MAX = 1024

# Valeur d'expiration pour un blocage permanent (Blacklist).
PERMANENT = 0.0

# (horodatage, ip du pair, taille, entrant, port du pair)
Packet = tuple[float, str, int, bool, int]
# Nombre max d'IP mémorisées pour ne signaler qu'une fois un refus du bouclier auto.
GUARD_REPORTED_MAX = 1024

logger = logging.getLogger(__name__)


def is_blocked(blocked: MutableMapping[str, float], ip: str, now: float) -> bool:
    """``blocked`` : ip -> expiration (epoch) ; PERMANENT = jamais."""
    expiry = blocked.get(ip)
    if expiry is None:
        return False
    return expiry == PERMANENT or now < expiry


def should_drop(
    inbound: bool,
    src: str,
    dst: str,
    blocked: MutableMapping[str, float],
    total: MutableMapping[str, float],
    now: float,
    total_on: bool = True,
    relay_block: bool = False,
    relay_traffic: bool = False,
) -> bool:
    """Décision par paquet (aucune modification, aucune création de paquet).

    ``relay_block`` (réglage « relais Rockstar » = bloquer) : un paquet de/vers une IP
    Rockstar est jeté SEULEMENT si ``relay_traffic`` (network.relay.is_relay_traffic :
    UDP, port 6672, hors tailles heartbeat/matchmaking). Authentification, Social Club,
    matchmaking : jamais jetés. Par défaut False : comportement v3.6.1.

    Entrant : rejeté si la source est bloquée. Sortant : rejeté UNIQUEMENT si la
    destination exacte est en coupure sortante (mode blocage total) et toujours
    bloquée en entrant. En cas d'erreur, le paquet passe (fail-safe)."""
    try:
        if (
            relay_block
            and relay_traffic
            and is_rockstar_server(src if inbound else dst)
        ):
            return True
        if inbound:
            return is_blocked(blocked, src, now)
        if not total_on:  # mode blocage total OFF : aucun sortant n'est jeté
            return False
        expiry = total.get(dst)
        return expiry is not None and now < expiry and is_blocked(blocked, dst, now)
    except Exception:
        return False


@dataclass
class LivePolicy:
    """Décisions du lot 2, côté capture, par paquet ENTRANT (IP du pair = source).

    - ``offenders`` + ``offender_drop`` : un récidiviste connu est jeté dès son premier
      paquet (coupure immédiate).
    - ``lock_on`` (verrou de session) : une IP absente de ``seen`` est jetée. Tant que
      le verrou est désactivé, chaque IP entrante est mémorisée dans ``seen`` (borné).
    - ``friends`` : liste d'amis, toujours autorisés (verrou, récidivistes, panique).
    - ``panic`` (bouton panique) : toute IP de joueur hors liste d'amis est jetée.
    - ``bypass(ip)`` : point d'accroche supplémentaire (vrai = jamais jeté ici).

    Les serveurs Rockstar ne sont JAMAIS jetés ici. Les paquets sortants ne sont
    jamais concernés. Toute erreur = le paquet passe (fail-safe)."""

    lock_on: bool = False
    seen: set[str] = field(default_factory=set)
    offenders: Collection[str] = field(default_factory=frozenset)
    offender_drop: bool = False
    friends: Collection[str] = field(default_factory=frozenset)
    panic: bool = False
    bypass: Callable[[str], bool] | None = None
    max_seen: int = MAX_SEEN

    def drop(self, inbound: bool, ip: str) -> bool:
        if not inbound:
            return False
        try:
            if is_rockstar_server(ip) or ip in self.friends:
                return False
            if self.bypass is not None and self.bypass(ip):
                return False
            if self.panic:
                return True
            if self.offender_drop and ip in self.offenders:
                return True
            if ip in self.seen:
                return False
            if self.lock_on:
                return True
            if len(self.seen) < self.max_seen:
                self.seen.add(ip)
            return False
        except Exception:
            return False


def handle_packet(
    w: Any,
    packet: Any,
    blocked: MutableMapping[str, float],
    total: MutableMapping[str, float],
    now: float,
    total_on: bool = True,
    relay_block: bool = False,
    policy: LivePolicy | None = None,
) -> bool:
    """Réinjecte le paquet ORIGINAL tel quel (``w.send(packet)``) ou le jette.
    Renvoie True si envoyé. Jamais de paquet fabriqué ni modifié. ``policy`` :
    verrou de session / récidivistes (lot 2), None = comportement du lot 1."""
    try:
        inbound = bool(packet.is_inbound)
        outbound = bool(packet.is_outbound)
        relay_traffic = relay_block and relay_packet(packet)
        drop = (inbound or outbound) and should_drop(
            inbound,
            packet.ip.src_addr,
            packet.ip.dst_addr,
            blocked,
            total,
            now,
            total_on,
            relay_block,
            relay_traffic,
        )
        if not drop and policy is not None:
            drop = policy.drop(inbound, packet.ip.src_addr)
    except Exception:
        drop = False
    if drop:
        return False
    w.send(packet)
    return True


def relay_packet(packet: Any) -> bool:
    """Métadonnées seulement (protocole, port, taille) ; toute erreur = False (passe).
    Le port de jeu est le port de destination dans les deux sens (filtre WinDivert :
    entrant vers notre 6672, sortant vers le 6672 du pair)."""
    try:
        udp = getattr(packet, "udp", None) is not None
        return is_relay_traffic(udp, int(packet.dst_port), len(packet.payload))
    except Exception:
        return False


def read_flag(flag: Any) -> bool:
    """Lit le drapeau partagé du blocage total ; toute erreur = False (le trafic passe)."""
    if flag is None:
        return False
    try:
        return bool(flag.value)
    except Exception:
        logger.debug("read_flag: lecture du drapeau impossible", exc_info=True)
        return False


def capture_loop(
    blocked: MutableMapping[str, float],
    out: Queue[Packet],
    extra_ports: bool,
    total_blocked: MutableMapping[str, float] | None = None,
    total_flag: Any = None,
    relay_flag: Any = None,
    lock_flag: Any = None,
    offender_flag: Any = None,
    offenders: MutableMapping[str, float] | None = None,
    panic_flag: Any = None,
    friends: MutableMapping[str, str] | None = None,
) -> None:  # pragma: no cover - nécessite Windows + WinDivert
    from network.sessions import open_windivert, packet_filter

    with (
        contextlib.suppress(KeyboardInterrupt),
        open_windivert(priority=LIVE_PRIORITY, filter_=packet_filter(extra_ports)) as w,
    ):
        # Copie locale de la liste partagée, rafraîchie toutes les BLOCKLIST_REFRESH s :
        # évite un aller-retour inter-processus par paquet (latence en jeu).
        local: dict[str, float] = dict(blocked)
        local_total: dict[str, float] = {}
        total_on = False
        relay_on = False
        next_refresh = 0.0
        # IP déjà vues dans CETTE session (processus de capture = durée de la session).
        policy = LivePolicy()
        for packet in w:
            inbound = bool(packet.is_inbound)
            ip = packet.ip.src_addr if inbound else packet.ip.dst_addr
            now = time.time()
            if now >= next_refresh:
                local = dict(blocked)
                local_total = dict(total_blocked) if total_blocked is not None else {}
                total_on = read_flag(total_flag)
                relay_on = read_flag(relay_flag)
                policy.lock_on = read_flag(lock_flag)
                policy.offender_drop = read_flag(offender_flag)
                policy.panic = read_flag(panic_flag)
                with contextlib.suppress(Exception):
                    policy.friends = (
                        frozenset(friends) if friends is not None else frozenset()
                    )
                with contextlib.suppress(Exception):
                    policy.offenders = (
                        frozenset(offenders) if offenders is not None else frozenset()
                    )
                next_refresh = now + BLOCKLIST_REFRESH
            handle_packet(
                w, packet, local, local_total, now, total_on, relay_on, policy
            )
            with contextlib.suppress(queue.Full):
                port = packet.src_port if inbound else packet.dst_port
                out.put_nowait((now, ip, len(packet.payload), inbound, int(port or 0)))


# -- compteur de joueurs en direct ------------------------------------------------
# Un joueur = IP de pair vue récemment sur les ports de Guardian (le flux de la vue
# en direct est déjà limité par packet_filter). Inactif depuis PLAYER_TIMEOUT_SECONDS
# (horloge monotone) : il n'est plus compté.
PLAYER_TIMEOUT_SECONDS = 60.0
# Borne mémoire du compteur (au-delà, le joueur le plus ancien est oublié).
MAX_PLAYERS = 1024


class PlayerCounter:
    """Dernier passage (monotone) par IP de pair, O(1) par paquet, borné et purgé.

    Alimenté côté affichage (jamais dans capture_loop) avec les seules métadonnées
    déjà transmises, et UNIQUEMENT pour les paquets entrants (IP du pair = source) :
    une destination usurpée/arbitraire n'est jamais comptée. Aucun verrou."""

    def __init__(
        self,
        timeout: float = PLAYER_TIMEOUT_SECONDS,
        max_players: int = MAX_PLAYERS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.timeout = timeout
        self.max_players = max_players
        self.clock = clock
        self.last_seen: dict[str, float] = {}  # ordre d'insertion = ordre d'activité
        self.full = False  # saturation déjà journalisée
        self.servers: dict[str, float] = {}  # serveurs Rockstar, jamais des joueurs

    def seen_server(self, ip: str) -> None:
        if ip in self.servers or len(self.servers) < self.max_players:
            self.servers[ip] = self.clock()

    def server_count(self) -> int:
        limit = self.clock() - self.timeout
        for ip in [ip for ip, ts in self.servers.items() if ts <= limit]:
            del self.servers[ip]
        return len(self.servers)

    def seen(self, ip: str) -> None:
        """O(1) : suppression/insertion dans un dict, éviction du plus ancien."""
        last = self.last_seen
        if ip in last:
            del last[ip]  # remis en fin : le plus ancien reste en tête
        elif len(last) < self.max_players:
            self.full = False  # repassé sous la borne : réarmé
        else:
            del last[next(iter(last))]
            if not self.full:
                self.full = True
                logger.debug("Compteur de joueurs saturé (%d)", self.max_players)
        last[ip] = self.clock()

    def purge(self) -> None:
        limit = self.clock() - self.timeout
        last = self.last_seen
        while last:
            ip = next(iter(last))
            if last[ip] > limit:
                break
            del last[ip]
        if len(last) < self.max_players:
            self.full = False

    def saturated(self) -> bool:
        return len(self.last_seen) >= self.max_players

    def players(self) -> list[str]:
        self.purge()
        return list(self.last_seen)

    def counts(
        self, ctrl: LiveSessionController, now: float | None = None
    ) -> tuple[int, int, int, int]:
        """(total, normaux, bloqués, coupés). Bloqué : Blacklist ou blocage auto.
        Coupé : sortant actuellement coupé par le blocage total. Une seule copie de
        chaque dict partagé (Manager) par appel, jamais un accès par IP."""
        now = ctrl.clock() if now is None else now
        try:
            blocked = dict(ctrl.blocked)
        except Exception:
            blocked = {}
        try:
            total_on = bool(ctrl.total_block)
        except Exception:
            total_on = False
        cuts: dict[str, float] = {}
        if total_on:
            try:
                cuts = dict(ctrl.total_blocked)
            except Exception:
                cuts = {}
        normal = n_blocked = cut = 0
        for ip in self.players():
            if is_blocked(blocked, ip, now):
                n_blocked += 1
            elif now < cuts.get(ip, 0.0):
                cut += 1
            else:
                normal += 1
        return normal + n_blocked + cut, normal, n_blocked, cut


_ROCKSTAR_BLOCKS: set[Any] | None = None


def is_rockstar_server(ip: str) -> bool:
    """IP dans les plages Take-Two/Rockstar STATIQUES (AS202021, AS46555 ; voir
    util/dynamicblacklist.py). Aucun appel réseau. Ne lève jamais."""
    global _ROCKSTAR_BLOCKS
    try:
        if _ROCKSTAR_BLOCKS is None:
            from util.dynamicblacklist import T2_EU_FALLBACK, T2_US_FALLBACK
            from util.network import construct_cidr_block_set

            _ROCKSTAR_BLOCKS = construct_cidr_block_set(
                sorted(T2_EU_FALLBACK | T2_US_FALLBACK)
            )
        from util.network import ip_in_cidr_block_set

        return bool(ip_in_cidr_block_set(ip, _ROCKSTAR_BLOCKS))
    except Exception:
        return False


def note_player(counter: PlayerCounter, ip: str, inbound: bool) -> None:
    """Anti-usurpation : seul un paquet ENTRANT compte (IP du pair = source).
    Une destination sortante (arbitraire) n'est jamais comptée. Les serveurs
    Rockstar sont comptés à part, jamais comme joueurs."""
    if inbound:
        if is_rockstar_server(ip):
            counter.seen_server(ip)
        else:
            counter.seen(ip)


def players_line(counter: PlayerCounter, ctrl: LiveSessionController) -> str:
    total, normal, blocked, cut = counter.counts(ctrl)
    n = (
        t("live.players_full", max=counter.max_players)
        if counter.saturated()
        else str(total)
    )
    line = t("live.players", n=n, normal=normal, blocked=blocked, cut=cut)
    servers = counter.server_count()
    if servers:
        line += "  " + t("live.servers", n=servers)
    return line


def blacklist_label(pseudo: str, when: datetime) -> str:
    """Nom enregistré dans la Blacklist : pseudo/note + date de blocage."""
    stamp = when.strftime("%Y-%m-%d %H:%M:%S")
    pseudo = pseudo.strip()
    if pseudo:
        return t("live.label", pseudo=pseudo, date=stamp)
    return t("live.label_nopseudo", date=stamp)


def make_auto_block_guard(
    whitelist_ips: set[str], dynamic_blocks: set[Any]
) -> Callable[[str], bool]:
    """IP que le bouclier AUTO ne doit jamais bloquer : liste blanche, plages
    Rockstar/Take-Two (sessions.py) et plages R*/Azure dynamiques (dynamicblacklist)."""
    from network.sessions import is_rockstar_ip
    from util.network import ip_in_cidr_block_set

    def guard(ip: str) -> bool:
        if ip in whitelist_ips:
            return True
        try:
            return is_rockstar_ip(ip) or ip_in_cidr_block_set(ip, dynamic_blocks)
        except Exception:
            return True  # dans le doute, ne pas bloquer automatiquement

    return guard


class LiveSessionController:
    """Logique de blocage/déblocage (testable sans console ni WinDivert)."""

    def __init__(
        self,
        blocked: MutableMapping[str, float],
        blacklist: Any,
        auto_block: bool = AUTO_BLOCK_DEFAULT,
        clock: Callable[[], float] = time.time,
        auto_block_guard: Callable[[str], bool] | None = None,
        reporter: Callable[[str, str, str], None] | None = None,
        auto_block_available: bool = True,
        auto_store: Any = None,
        auto_entries: dict[str, float] | None = None,
        total_block: bool = TOTAL_BLOCK_DEFAULT,
        total_blocked: MutableMapping[str, float] | None = None,
        total_flag: Any = None,
        relay_mode: str = RELAY_DEFAULT,
        relay_flag: Any = None,
        session_lock: bool = SESSION_LOCK_DEFAULT,
        lock_flag: Any = None,
        offenders: Any = None,
        offender_ips: MutableMapping[str, float] | None = None,
        offender_sound: bool = OFFENDER_SOUND_DEFAULT,
        offender_drop: bool = OFFENDER_DROP_DEFAULT,
        offender_flag: Any = None,
        sound: Callable[[], Any] = beep,
        friends: MutableMapping[str, str] | None = None,
        panic_flag: Any = None,
    ) -> None:
        self.blocked = blocked
        # Liste d'amis ip -> pseudo (copie partagée lue par la capture) ; panique.
        self.friends: MutableMapping[str, str] = friends if friends is not None else {}
        self.panic_flag = panic_flag
        self.panic = False
        # Lot 2. Drapeaux partagés avec la capture (multiprocessing.Value) ou None.
        self.lock_flag = lock_flag
        self.offender_flag = offender_flag
        self.session_lock = session_lock
        self.offender_drop = offender_drop
        self.offender_sound = offender_sound
        self.sound = sound
        # OffenderStore (network/offenders.py) ou None ; ``offender_ips`` est la copie
        # partagée (Manager) lue par la capture pour la coupure immédiate.
        self.offenders = offenders
        self.offender_ips: MutableMapping[str, float] = (
            offender_ips if offender_ips is not None else {}
        )
        self._offender_alerted: set[str] = set()
        if offenders is not None:
            with contextlib.suppress(Exception):
                for ip in offenders.ips():
                    if not is_rockstar_server(ip):
                        self.offender_ips[ip] = 1.0
        # Réglage « relais Rockstar » (autoriser/bloquer), partagé avec la capture.
        self.relay_flag = relay_flag
        self.relay_mode = relay_mode
        # reporter(ip, type « auto »/« manual », pseudo) : rapport d'incident à chaque blocage.
        self.reporter = reporter
        # Faux si les plages Rockstar/Azure sont inconnues : bouclier auto interdit.
        self.auto_block_available = auto_block_available
        auto_block = auto_block and auto_block_available
        # Concerne UNIQUEMENT le blocage automatique ; le blocage manuel (B) peut
        # bloquer n'importe quelle IP choisie par l'utilisateur.
        self.auto_block_guard = auto_block_guard or (lambda _ip: False)
        self._guard_reported: set[str] = set()
        self.blacklist = blacklist
        self.auto_block = auto_block
        # Mode blocage total : coupe aussi le SORTANT vers l'IP bloquée, 10 min, en mémoire.
        self.total_blocked: MutableMapping[str, float] = (
            total_blocked if total_blocked is not None else {}
        )
        # Drapeau partagé avec le processus de capture (multiprocessing.Value) ou None.
        self.total_flag = total_flag
        self.total_block = total_block and auto_block_available
        self.clock = clock
        self.pseudos: dict[str, str] = {}
        self.events: list[str] = []
        # Dernier message de bascule (A/T) : une seule ligne, remplacée, effacée après
        # TOGGLE_MSG_SECONDS. (texte, instant d'affichage selon self.clock)
        self.toggle_msg: tuple[str, float] | None = None
        # Les IP déjà en Blacklist restent bloquées dans cette vue aussi.
        for ip, _name in list(blacklist):
            self.blocked[ip] = PERMANENT
        # Blocages auto persistants (auto_block.json) : ip -> expiration.
        # ``auto_store`` expose request(dict) (AutoBlockSaver) ; None = mémoire seule.
        self.auto_store = auto_store
        self.auto_entries: dict[str, float] = {}
        if (
            auto_block_available
        ):  # sans plages R*/Azure, impossible de filtrer : ignorés
            for ip, expiry in (auto_entries or {}).items():
                if ip in self.blocked or self.auto_block_guard(ip):
                    continue
                self.auto_entries[ip] = expiry
                self.blocked[ip] = expiry

    def _cut_outbound(self, ip: str) -> None:
        """Coupure sortante (blocage total) si autorisée ; mêmes garde-fous que l'auto."""
        if not (self.total_block and self.auto_block_available):
            return
        if is_rockstar_server(ip):
            self.events.append(t("live.ev.total_skipped", ip=ip))
            return
        try:
            if self.auto_block_guard(ip):
                self.events.append(t("live.ev.total_skipped", ip=ip))
                return
        except Exception:
            return
        self.total_blocked[ip] = self.clock() + TOTAL_BLOCK_SECONDS
        self.events.append(t("live.ev.total", ip=ip, minutes=TOTAL_BLOCK_SECONDS // 60))

    @property
    def total_block(self) -> bool:
        return self._total_block

    @total_block.setter
    def total_block(self, on: bool) -> None:
        self._total_block = bool(on)
        if self.total_flag is not None:
            with contextlib.suppress(Exception):
                self.total_flag.value = self._total_block
        if not self._total_block:
            # OFF : toutes les coupures sortantes en cours sont levées tout de suite.
            # Le blocage ENTRANT ne change pas (7 jours auto, permanent pour B).
            cleared = len(self.total_blocked)
            self.total_blocked.clear()
            if cleared and hasattr(self, "events"):
                self.events.append(t("live.ev.total_cleared", n=cleared))

    @staticmethod
    def _write_flag(flag: Any, value: bool) -> None:
        if flag is not None:
            with contextlib.suppress(Exception):
                flag.value = value

    @property
    def session_lock(self) -> bool:
        return self._session_lock

    @session_lock.setter
    def session_lock(self, on: bool) -> None:
        self._session_lock = bool(on)
        self._write_flag(self.lock_flag, self._session_lock)

    @property
    def offender_drop(self) -> bool:
        return self._offender_drop

    @offender_drop.setter
    def offender_drop(self, on: bool) -> None:
        self._offender_drop = bool(on)
        self._write_flag(self.offender_flag, self._offender_drop)

    @property
    def panic(self) -> bool:
        return self._panic

    @panic.setter
    def panic(self, on: bool) -> None:
        self._panic = bool(on)
        self._write_flag(self.panic_flag, self._panic)

    def toggle_panic(self) -> None:
        self.panic = not self.panic

    def is_friend(self, ip: str) -> bool:
        try:
            return ip in self.friends
        except Exception:
            return False

    def add_friend(self, ip: str, nick: str) -> bool:
        """Ajoute un ami (pseudo tronqué). Refusé : serveur Rockstar, liste pleine.
        Un ami est retiré des blocages et des récidivistes (toujours autorisé)."""
        nick = " ".join(nick.split())[:MAX_NICK] or ip
        if is_rockstar_server(ip):
            return False
        if ip not in self.friends and len(self.friends) >= MAX_FRIENDS:
            self.events.append(t("live.ev.friends_full", max=MAX_FRIENDS))
            return False
        if ip in self.blocked or ip in self.offender_ips:
            self.unblock(ip)
        self.friends[ip] = nick
        self.events.append(t("live.ev.friend_added", ip=ip, nick=nick))
        return True

    def remove_friend(self, ip: str) -> bool:
        nick = self.friends.pop(ip, None)
        if nick is None:
            return False
        self.events.append(t("live.ev.friend_removed", ip=ip, nick=nick))
        return True

    def label(self, ip: str) -> str:
        """Pseudo d'ami à la place de l'IP, sinon l'IP."""
        try:
            return self.friends.get(ip) or ip
        except Exception:
            return ip

    def toggle_session_lock(self) -> None:
        self.session_lock = not self.session_lock

    def toggle_offender_drop(self) -> None:
        self.offender_drop = not self.offender_drop

    def toggle_offender_sound(self) -> None:
        self.offender_sound = not self.offender_sound

    def _record_offender(self, ip: str, reason: str) -> None:
        """Mémorise un blocage (métadonnées seules) ; jamais un serveur Rockstar."""
        if self.offenders is None or is_rockstar_server(ip) or self.is_friend(ip):
            return
        with contextlib.suppress(Exception):
            if self.offenders.record(ip, reason, self.clock()):
                self.offender_ips[ip] = 1.0
                self._offender_alerted.add(ip)  # bloqué maintenant : pas d'alerte

    def offender_check(self, ip: str, inbound: bool) -> str | None:
        """Paquet ENTRANT d'un récidiviste connu : une ligne d'alerte (une fois par
        session et par IP) + alerte sonore si activée. Renvoie la ligne ou None."""
        if not inbound or self.offenders is None or ip in self._offender_alerted:
            return None
        if self.is_friend(ip):
            return None
        try:
            entry = self.offenders.get(ip)
            if entry is None or is_rockstar_server(ip):
                return None
            if len(self._offender_alerted) >= OFFENDER_ALERTED_MAX:
                self._offender_alerted.clear()
            self._offender_alerted.add(ip)
            last = (
                datetime.fromtimestamp(entry.last, tz=UTC)
                .astimezone()
                .strftime("%Y-%m-%d %H:%M")
            )
            line = t(
                "live.ev.offender",
                ip=ip,
                count=entry.count,
                last=last,
                reason=t(entry.reason) if entry.reason else "?",
                action=t(
                    "live.offender_cut" if self.offender_drop else "live.offender_alert"
                ),
            )
        except Exception:
            return None
        self.events.append(line)
        if self.offender_sound:
            with contextlib.suppress(Exception):
                self.sound()
        return line

    @property
    def relay_mode(self) -> str:
        return self._relay_mode

    @relay_mode.setter
    def relay_mode(self, mode: str) -> None:
        self._relay_mode = normalize(mode)
        if self.relay_flag is not None:
            with contextlib.suppress(Exception):
                self.relay_flag.value = is_block(self._relay_mode)

    @property
    def relay_block(self) -> bool:
        return is_block(self.relay_mode)

    def toggle_relay(self) -> None:
        self.relay_mode = toggled(self.relay_mode)

    def toggle_total_block(self) -> None:
        self.total_block = self.auto_block_available and not self.total_block

    def _persist(self) -> None:
        if self.auto_store is not None:
            with contextlib.suppress(Exception):
                self.auto_store.request(self.auto_entries)

    def block(self, ip: str, pseudo: str = "") -> None:
        """Blocage MANUEL immédiat, écrit de façon PERMANENTE dans la Blacklist
        (data.json). Le bouclier auto, lui, bloque 7 jours via auto_block.json.
        Refusé pour un serveur Rockstar (on se couperait de la session)."""
        if is_rockstar_server(ip):
            self.events.append(t("live.ev.rockstar_refused", ip=ip))
            return
        pseudo = pseudo or self.pseudos.get(ip, "")
        self.blocked[ip] = PERMANENT
        if self.auto_entries.pop(ip, None) is not None:  # devient permanent (data.json)
            self._persist()
        self.blacklist.add(ip, blacklist_label(pseudo, datetime.now()))
        self.blacklist.save()
        self.events.append(t("live.ev.blocked", ip=ip))
        self._record_offender(ip, MANUAL_REASON)
        self._cut_outbound(ip)
        self._report(ip, "manual", pseudo)

    def _report(self, ip: str, kind: str, pseudo: str) -> None:
        if self.reporter is None:
            return
        # Un rapport ne doit jamais empêcher un blocage.
        with contextlib.suppress(Exception):
            self.reporter(ip, kind, pseudo)

    def toggle_auto_block(self) -> None:
        self.auto_block = self.auto_block_available and not self.auto_block

    def auto_block_if_needed(self, peer: PeerState) -> bool:
        if (
            not self.auto_block
            or not self.auto_block_available
            or peer.level < Level.SUSPECT
            or is_rockstar_server(peer.ip)
        ):
            return False
        if peer.ip in self.blocked:
            return False
        if self.auto_block_guard(peer.ip) or self.is_friend(peer.ip):
            if peer.ip not in self._guard_reported:
                if len(self._guard_reported) >= GUARD_REPORTED_MAX:
                    self._guard_reported.clear()
                self._guard_reported.add(peer.ip)
                self.events.append(t("live.ev.auto_skipped", ip=peer.ip))
            return False
        # Jamais écrit dans data.json : fichier séparé auto_block.json, expire seul.
        from network.autoblock import MAX_ENTRIES, cap

        expiry = self.clock() + AUTO_BLOCK_SECONDS
        self.blocked[peer.ip] = expiry
        self.auto_entries[peer.ip] = expiry
        if len(self.auto_entries) > MAX_ENTRIES:
            kept = cap(self.auto_entries, MAX_ENTRIES)
            for ip in set(self.auto_entries) - set(kept):
                self.blocked.pop(ip, None)
            self.auto_entries = kept
        self._persist()
        self.events.append(
            t(
                "live.ev.auto",
                ip=peer.ip,
                reason=t(peer.reason_key or "reason.burst"),
                days=AUTO_BLOCK_SECONDS // 86400,
            )
        )
        self._record_offender(peer.ip, peer.reason_key or "reason.burst")
        self._cut_outbound(peer.ip)
        self._report(peer.ip, "auto", self.pseudos.get(peer.ip, ""))
        return True

    def unblock(self, ip: str, remove_from_blacklist: bool = True) -> None:
        self.blocked.pop(ip, None)
        self.total_blocked.pop(ip, None)
        if self.auto_entries.pop(ip, None) is not None:
            self._persist()
        if remove_from_blacklist and ip in self.blacklist:
            self.blacklist.remove(ip)
            self.blacklist.save()
        # Déblocage manuel : l'IP n'est plus un récidiviste.
        self.offender_ips.pop(ip, None)
        self._offender_alerted.discard(ip)
        if self.offenders is not None:
            with contextlib.suppress(Exception):
                self.offenders.remove(ip)
        self.events.append(t("live.ev.unblocked", ip=ip))

    def expire(self) -> None:
        now = self.clock()
        for ip, expiry in list(self.blocked.items()):
            if expiry != PERMANENT and now >= expiry:
                self.blocked.pop(ip, None)
                self.events.append(t("live.ev.expired", ip=ip))
        for ip, expiry in list(self.total_blocked.items()):
            if now >= expiry:
                self.total_blocked.pop(ip, None)
                self.events.append(t("live.ev.total_expired", ip=ip))
        expired = [ip for ip, e in self.auto_entries.items() if now >= e]
        for ip in expired:
            del self.auto_entries[ip]
        if expired:
            self._persist()

    def block_status(self, ip: str) -> str:
        expiry = self.blocked.get(ip)
        if expiry is None:
            return ""
        if ip in self.total_blocked:
            return t("live.blocked_total")
        if expiry == PERMANENT:
            return t("live.blocked")
        left = max(0, int(expiry - self.clock()))
        if left >= 86400:
            return t("live.blocked_days", d=left // 86400 + 1)
        if left >= 3600:
            return t("live.blocked_hours", h=left // 3600 + 1)
        return t("live.blocked_min", m=left // 60 + 1)


LEVEL_COLORS = {
    Level.NORMAL: "",
    Level.INHABITUEL: Fore.YELLOW,  # orange (pas d'orange en ANSI 16 couleurs)
    Level.SUSPECT: Fore.LIGHTRED_EX,
}


TOGGLE_MSG_SECONDS = 4.0


def set_toggle_msg(ctrl: LiveSessionController, text: str) -> None:
    """Remplace le message de bascule courant (jamais empilé)."""
    ctrl.toggle_msg = (text, ctrl.clock())


def toggle_line(ctrl: LiveSessionController) -> list[str]:
    """Ligne du dernier message de bascule, vide une fois expirée."""
    msg = getattr(ctrl, "toggle_msg", None)
    if msg is None:
        return []
    text, since = msg
    if ctrl.clock() - since > TOGGLE_MSG_SECONDS:
        ctrl.toggle_msg = None
        return []
    return [text]


def status_word(enabled: bool) -> str:
    """Mot d'état (ACTIVÉ/désactivé, ON/off) seul en couleur : vert si actif, rouge
    sinon. Les séquences ANSI sont ignorées par ``fit_line`` (largeur intacte)."""
    if enabled:
        return Fore.GREEN + t("live.on") + Style.RESET_ALL
    return Fore.RED + t("live.off") + Style.RESET_ALL


def relay_word(ctrl: LiveSessionController) -> str:
    """« autoriser » en vert (défaut), « bloquer » en rouge."""
    if ctrl.relay_block:
        return Fore.RED + t("live.relay_block") + Style.RESET_ALL
    return Fore.GREEN + t("live.relay_allow") + Style.RESET_ALL


def recording_status(active: bool, path: str = "") -> str:
    """État de l'enregistrement pour l'en-tête (seul le mot d'état est coloré)."""
    if active:
        return t("live.rec_on", on=status_word(True), path=path)
    return status_word(False)


def render_head(
    ctrl: LiveSessionController, recording: str, players: PlayerCounter | None = None
) -> list[str]:
    return [
        Style.BRIGHT + t("live.title") + Style.RESET_ALL,
        *([players_line(players, ctrl)] if players is not None else []),
        t(
            "live.status",
            days=AUTO_BLOCK_SECONDS // 86400,
            auto=status_word(ctrl.auto_block),
            hint="" if ctrl.auto_block else t("live.auto_hint"),
            rec=recording,
        ),
        t(
            "live.total_status",
            minutes=TOTAL_BLOCK_SECONDS // 60,
            state=status_word(ctrl.total_block),
        ),
        t("live.total_warning"),
        t("live.relay_status", state=relay_word(ctrl)),
        t("live.lock_status", state=status_word(ctrl.session_lock)),
        t(
            "live.panic_status",
            state=(Fore.LIGHTRED_EX + t("live.panic_on") + Style.RESET_ALL)
            if ctrl.panic
            else status_word(False),
            n=len(ctrl.friends),
        ),
        t(
            "live.offender_status",
            n=len(ctrl.offenders) if ctrl.offenders is not None else 0,
            sound=status_word(ctrl.offender_sound),
            cut=status_word(ctrl.offender_drop),
        ),
        *(
            []
            if ctrl.auto_block_available
            else [Fore.LIGHTRED_EX + t("live.no_ranges") + Style.RESET_ALL]
        ),
        "",
        t(
            "live.header",
            n="#",
            ip="IP",
            country=t("live.col.country"),
            seen=t("live.col.seen"),
            pps=t("live.col.pps"),
            bps=t("live.col.bps"),
            avg=t("live.col.avg"),
            max=t("live.col.max"),
            state=t("live.col.state"),
        ),
    ]


def render(
    monitor: SessionMonitor,
    ctrl: LiveSessionController,
    peers: list[PeerState],
    recording: str,
    now: float,
    players: PlayerCounter | None = None,
    size: tuple[int, int] | None = None,
    page: int = 0,
) -> str:
    """Frame complète. Avec ``size=(colonnes, lignes)``, la frame tient dans la fenêtre :
    en-tête en haut, barre de touches en bas, tableau paginé, lignes tronquées."""
    head = render_head(ctrl, recording, players)
    rows: list[str] = []
    alerts = []
    for i, p in enumerate(peers, 1):
        s = p.window.stats(now)
        server = is_rockstar_server(p.ip)
        if server:
            state = t("live.rockstar_server")
        else:
            state = ctrl.block_status(p.ip) or (
                t("level.learning")
                if p.learning(now)
                else t(LEVEL_KEYS[Level(p.level)])
            )
        try:
            first = (
                datetime.fromtimestamp(p.first_seen, tz=UTC)
                .astimezone()
                .strftime("%H:%M:%S")
            )
        except (OSError, OverflowError, ValueError):
            first = "??:??:??"
        row = (
            f"{i:>2}  {ctrl.label(p.ip)[:15]:<15}  {(country_code(p.ip) or '—'):<5}  {first:<10}  "
            f"{s.pps:>6.0f}  {s.bps:>8.0f}  {s.avg_size:>5.0f}  {s.max_size:>5}  "
            f"{state:<10}  {ctrl.pseudos.get(p.ip, '')}"
        )
        color = Fore.CYAN if server else LEVEL_COLORS[p.level]
        rows.append(color + row + Style.RESET_ALL if color else row)
        if p.alert:
            alerts.append(color + p.alert + Style.RESET_ALL)
    if not peers:
        rows.append(t("live.no_peers"))
    tail = ["", *alerts, *ctrl.events[-5:], *toggle_line(ctrl), "", t("live.keys")]
    if size is None:
        return "\n".join(head + rows + tail)
    width, height = size
    return "\n".join(
        fit_line(line, width)
        for line in fit_frame(head, rows, tail, height, page, len(peers))
    )


_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def fit_line(line: str, width: int) -> str:
    """Tronque à ``width - 1`` caractères visibles (séquences ANSI ignorées) pour ne
    jamais déclencher le retour à la ligne automatique de la console."""
    limit = max(1, width - 1)
    out: list[str] = []
    visible = 0
    pos = 0
    truncated = False
    while pos < len(line):
        m = _ANSI.match(line, pos)
        if m:
            out.append(m.group())
            pos = m.end()
            continue
        if visible >= limit:
            truncated = True
            break
        out.append(line[pos])
        visible += 1
        pos += 1
    result = "".join(out)
    if truncated and "\x1b[" in result:
        result += Style.RESET_ALL
    return result


def paginate(total: int, per_page: int, page: int) -> tuple[int, int, int, int]:
    """(début, fin, page bornée, nombre de pages) — indices 0-based, fin exclue."""
    per_page = max(1, per_page)
    pages = max(1, -(-total // per_page))
    page = min(max(0, page), pages - 1)
    start = page * per_page
    return start, min(total, start + per_page), page, pages


def fit_frame(
    head: list[str],
    rows: list[str],
    tail: list[str],
    height: int,
    page: int,
    total: int,
) -> list[str]:
    """Assemble une frame d'au plus ``height`` lignes : en-tête toujours en haut,
    barre de touches toujours en bas, tableau paginé entre les deux."""
    height = max(3, height)
    keys = tail[-1:]
    extra = tail[:-1]
    # Lignes réservées : en-tête + ligne de pagination + touches ; le reste au tableau,
    # puis aux alertes/événements seulement s'il reste de la place.
    head = head[: max(1, height - 2)]
    budget = height - len(head) - len(keys) - 1
    if total == 0:
        body = rows[: max(0, budget)]
        pager: list[str] = []
        budget += 1
    else:
        per_page = max(1, budget)
        start, end, page, pages = paginate(total, per_page, page)
        body = rows[start:end]
        pager = [
            t(
                "live.page",
                first=start + 1,
                last=end,
                total=total,
                page=page + 1,
                pages=pages,
            )
        ]
    room = height - len(head) - len(body) - len(pager) - len(keys)
    frame = head + body + pager + (extra[:room] if room > 0 else []) + keys
    return frame[:height] if len(frame) > height else frame


def rows_per_page(height: int, head_len: int) -> int:
    """Nombre de joueurs affichés par page pour une hauteur de fenêtre donnée."""
    return max(1, max(3, height) - min(head_len, max(1, height - 2)) - 2)


ALT_ON = "\x1b[?1049h\x1b[?25l"
ALT_OFF = "\x1b[?25h\x1b[?1049l"
HOME = "\x1b[H"
EOL = "\x1b[K"
EOS = "\x1b[J"


def enable_vt_mode() -> bool:
    """Active les séquences VT (ENABLE_VIRTUAL_TERMINAL_PROCESSING) sur la console
    Windows ; sans effet ailleurs. Ne lève jamais."""
    try:
        import colorama

        colorama.just_fix_windows_console()
    except Exception:
        logger.debug("colorama.just_fix_windows_console indisponible", exc_info=True)
    if sys.platform != "win32":
        return True
    try:
        import ctypes

        k32 = ctypes.windll.kernel32  # type: ignore[attr-defined,unused-ignore]
        handle = k32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not k32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(k32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        logger.debug("SetConsoleMode impossible", exc_info=True)
        return False


class LiveScreen:
    """Écran alternatif : la vue est redessinée sur place, sans remplir l'historique."""

    def __init__(self, out: Any = None) -> None:
        self.out = out if out is not None else sys.stdout
        self.active = False

    def write(self, text: str) -> None:
        self.out.write(text)
        self.out.flush()

    def enter(self) -> None:
        enable_vt_mode()
        self.write(ALT_ON + HOME + "\x1b[2J")
        self.active = True

    def draw(self, frame: str) -> None:
        body = (EOL + "\n").join(frame.split("\n"))
        self.write(HOME + body + EOL + EOS)

    def leave(self) -> None:
        if self.active:
            self.active = False
            with contextlib.suppress(Exception):
                self.write(Style.RESET_ALL + ALT_OFF)


PAGE_KEYS = {"pgdn": 1, "down": 1, "+": 1, "pgup": -1, "up": -1, "-": -1}
_SPECIAL = {"I": "pgup", "Q": "pgdn", "H": "up", "P": "down"}


def read_key(getwch: Callable[[], str], kbhit: Callable[[], bool]) -> str:
    """Lit une touche ; les touches spéciales (préfixe \\x00 / \\xe0) deviennent
    « pgup », « pgdn », « up », « down »."""
    key = getwch()
    if key in ("\x00", "\xe0"):
        code = getwch() if kbhit() else ""
        return _SPECIAL.get(code, "")
    return key.lower()


def page_step(key: str) -> int:
    return PAGE_KEYS.get(key, 0)


def clamp_page(
    page: int,
    total: int,
    height: int,
    ctrl: LiveSessionController,
    players: PlayerCounter | None = None,
) -> int:
    head = render_head(ctrl, "", players)
    return paginate(total, rows_per_page(height, len(head)), page)[2]


def handle_key(
    key: str,
    ctrl: LiveSessionController,
    peers: list[PeerState],
    blocked: MutableMapping[str, float],
    recorder: Any,
    prompt: Callable[[str], str],
    config: Any = None,
) -> None:
    """Action d'une touche de la vue en direct. Les bascules A/T n'affichent aucune
    invite : l'état change, est sauvegardé et la frame suivante l'affiche."""
    if key == "b":
        peer = _pick(peers, prompt(t("live.ask_block")))
        if peer and is_rockstar_server(peer.ip):
            ctrl.block(peer.ip)  # refusé, message dans les événements
        elif peer:
            ctrl.block(peer.ip, prompt(t("live.ask_pseudo")))
    elif key == "p":
        peer = _pick(peers, prompt(t("live.ask_row")))
        if peer:
            ctrl.pseudos[peer.ip] = prompt(t("live.ask_pseudo_for", ip=peer.ip)).strip()
    elif key == "d":
        ips = list(blocked.keys())
        listing = "\n".join(
            f"{i:>2}  {ip}  {ctrl.block_status(ip)}" for i, ip in enumerate(ips, 1)
        )
        answer = prompt(
            (listing + "\n" if listing else "") + t("live.ask_unblock")
        ).strip()
        if answer.isdigit() and 1 <= int(answer) <= len(ips):
            ctrl.unblock(ips[int(answer) - 1])
    elif key == "a":
        ctrl.toggle_auto_block()
        _save(config, AUTO_BLOCK_KEY, ctrl.auto_block)
        set_toggle_msg(
            ctrl, t("live.ev.auto_toggled", state=status_word(ctrl.auto_block))
        )
    elif key == "t":
        ctrl.toggle_total_block()
        _save(config, TOTAL_BLOCK_KEY, ctrl.total_block)
        set_toggle_msg(
            ctrl, t("live.ev.total_toggled", state=status_word(ctrl.total_block))
        )
    elif key == "l":
        ctrl.toggle_relay()
        if config is not None:
            try:
                config.data[RELAY_KEY] = ctrl.relay_mode
                config.save()
            except Exception:
                logger.debug("sauvegarde de %s impossible", RELAY_KEY, exc_info=True)
        set_toggle_msg(ctrl, t("live.ev.relay_toggled", state=relay_word(ctrl)))
    elif key == "v":
        ctrl.toggle_session_lock()
        _save(config, SESSION_LOCK_KEY, ctrl.session_lock)
        set_toggle_msg(
            ctrl, t("live.ev.lock_toggled", state=status_word(ctrl.session_lock))
        )
    elif key == "x":
        ctrl.toggle_panic()
        set_toggle_msg(ctrl, t("live.ev.panic_toggled", state=status_word(ctrl.panic)))
    elif key == "f":
        peer = _pick(peers, prompt(t("live.ask_friend")))
        if peer and ctrl.is_friend(peer.ip):
            ctrl.remove_friend(peer.ip)
            _save_friends(config, ctrl)
        elif peer and ctrl.add_friend(
            peer.ip, prompt(t("live.ask_friend_nick", ip=peer.ip))
        ):
            _save_friends(config, ctrl)
    elif key == "s":
        ctrl.toggle_offender_sound()
        _save(config, OFFENDER_SOUND_KEY, ctrl.offender_sound)
        set_toggle_msg(
            ctrl, t("live.ev.sound_toggled", state=status_word(ctrl.offender_sound))
        )
    elif key == "c":
        ctrl.toggle_offender_drop()
        _save(config, OFFENDER_DROP_KEY, ctrl.offender_drop)
        set_toggle_msg(
            ctrl, t("live.ev.cut_toggled", state=status_word(ctrl.offender_drop))
        )
    elif key == "e":
        if recorder.active:
            recorder.stop()
        else:
            recorder.start()


def make_prompt(screen: LiveScreen, frame: str, cols: int) -> Callable[[str], str]:
    """Invite affichée sous une frame réduite : en-tête et tableau restent visibles."""

    def prompt(text: str) -> str:
        screen.draw(frame)
        screen.write("\n\x1b[?25h")  # curseur visible pendant la saisie
        try:
            return input(fit_line(text, cols))
        finally:
            screen.write("\x1b[?25l")

    return prompt


def _save(config: Any, key: str, value: bool) -> None:
    if config is None:
        return
    try:
        config.data[key] = bool(value)
        config.save()
    except Exception:
        logger.debug("sauvegarde de %s impossible", key, exc_info=True)


def load_friends(raw: object) -> dict[str, str]:
    """Liste d'amis de data.json validée (IP valides, pseudos str, bornée)."""
    import ipaddress

    out: dict[str, str] = {}
    if not isinstance(raw, dict):
        return out
    for ip, nick in raw.items():
        if len(out) >= MAX_FRIENDS:
            break
        try:
            ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            continue
        if isinstance(nick, str) and not is_rockstar_server(ip):
            out[ip] = " ".join(nick.split())[:MAX_NICK] or ip
    return out


def _save_friends(config: Any, ctrl: LiveSessionController) -> None:
    if config is None:
        return
    try:
        config.data[FRIENDS_KEY] = dict(ctrl.friends)
        config.save()
    except Exception:
        logger.debug("sauvegarde de %s impossible", FRIENDS_KEY, exc_info=True)


def _pick(peers: list[PeerState], answer: str) -> PeerState | None:
    answer = answer.strip()
    if answer.isdigit() and 1 <= int(answer) <= len(peers):
        return peers[int(answer) - 1]
    return None


def _ask_row(peers: list[PeerState], prompt: str) -> PeerState | None:
    answer = input(prompt).strip()
    if answer.isdigit() and 1 <= int(answer) <= len(peers):
        return peers[int(answer) - 1]
    return None


class BackgroundSession:
    """Protection en direct qui survit à la vue : processus de capture (proc), dicts
    partagés (Manager), contrôleur (bouclier/total) et un fil léger qui fait ce que
    faisait la boucle d'affichage pour la protection (paquets, bouclier auto,
    expirations, purge). [R] quitte la vue en laissant tout tourner ; [Q] arrête."""

    def __init__(
        self,
        proc: Any,
        packets: Any,
        ctrl: LiveSessionController,
        monitor: SessionMonitor,
        counter: PlayerCounter,
        recorder: Any,
        closers: list[Callable[[], Any]] | None = None,
        config: Any = None,
        blocked: MutableMapping[str, float] | None = None,
        new_players: Any = None,
    ) -> None:
        import threading

        # NewPlayerTracker (alerte + journal) ou None.
        self.new_players = new_players
        self.proc = proc
        self.packets = packets
        self.ctrl = ctrl
        self.monitor = monitor
        self.counter = counter
        self.recorder = recorder
        self.closers = closers or []
        self.config = config
        self.blocked = ctrl.blocked if blocked is None else blocked
        self.peers: list[PeerState] = []
        self.now = time.time()
        self.lock = threading.RLock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._pump, name="live-bg", daemon=True)
        self.started = False
        self.stopped = False

    def start(self) -> None:
        if self.started:
            return
        self.started = True
        self.proc.start()
        self._thread.start()

    def alive(self) -> bool:
        if self.stopped:
            return False
        try:
            return bool(self.proc.is_alive())
        except Exception:
            return False

    def step(self, timeout: float = 0.02) -> None:
        """Un paquet au plus, puis évaluation si l'échéance est passée."""
        try:
            ts, ip, size, inbound, port = self.packets.get(timeout=timeout)
            with self.lock:
                self.recorder.write(ts, ip, size, inbound)
                note_player(self.counter, ip, inbound)
                if self.new_players is not None:
                    try:
                        alert = self.new_players.observe(ts, ip, inbound)
                    except Exception:
                        alert = None
                    if alert:
                        self.ctrl.events.append(alert)
                with contextlib.suppress(Exception):
                    self.ctrl.offender_check(ip, inbound)
                if inbound:
                    self.monitor.add_packet(ip, size, ts, port)
        except queue.Empty:
            pass

    def evaluate(self) -> None:
        with self.lock:
            now = time.time()
            self.ctrl.expire()
            peers = self.monitor.evaluate(now)
            for p in peers:
                try:
                    self.ctrl.auto_block_if_needed(p)
                except Exception:
                    logger.exception("bouclier auto : évaluation impossible")
            self.monitor.prune(now)
            self.peers, self.now = peers, now

    def _pump(self) -> None:
        next_eval = time.monotonic()
        while not self._stop.is_set():
            try:
                self.step()
                if time.monotonic() >= next_eval:
                    next_eval = time.monotonic() + EVAL_SECONDS
                    self.evaluate()
            except Exception:
                logger.exception("session en fond : itération impossible")
                self._stop.wait(0.2)

    def stop(self) -> None:
        """Arrêt complet, idempotent : fil, enregistrement, rapports, capture, Manager."""
        if self.stopped:
            return
        self.stopped = True
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=2)
        with contextlib.suppress(Exception):
            self.recorder.stop()
        for close in self.closers[:1]:
            with contextlib.suppress(Exception):
                close()
        if self.started:
            with contextlib.suppress(Exception):
                self.proc.terminate()
            with contextlib.suppress(Exception):
                self.proc.join(timeout=5)
        for close in self.closers[1:]:
            with contextlib.suppress(Exception):
                close()


_BACKGROUND: BackgroundSession | None = None


def background_session() -> BackgroundSession | None:
    """Session en fond encore vivante, sinon None (une session morte est nettoyée)."""
    global _BACKGROUND
    if _BACKGROUND is not None and not _BACKGROUND.alive():
        _BACKGROUND.stop()
        _BACKGROUND = None
    return _BACKGROUND


def attach_or_start(factory: Callable[[], BackgroundSession]) -> BackgroundSession:
    """Réattache la session en fond si elle tourne (aucun second handle WinDivert),
    sinon en crée et démarre une nouvelle."""
    global _BACKGROUND
    current = background_session()
    if current is not None:
        return current
    session = factory()
    session.start()
    _BACKGROUND = session
    return session


def stop_background() -> None:
    """Arrêt de la session en fond (touche Q, sortie du menu, atexit). Idempotent."""
    global _BACKGROUND
    session, _BACKGROUND = _BACKGROUND, None
    if session is not None:
        session.stop()


def background_status_line() -> str | None:
    """Ligne du menu principal tant que la protection tourne en fond."""
    session = background_session()
    if session is None:
        return None
    on, off = t("live.on"), t("live.off")
    return t(
        "live.bg_status",
        auto=on if session.ctrl.auto_block else off,
        total=on if session.ctrl.total_block else off,
    )


atexit.register(stop_background)


def live_view(
    session: BackgroundSession,
    getwch: Callable[[], str],
    kbhit: Callable[[], bool],
    screen: LiveScreen | None = None,
    max_frames: int | None = None,
) -> str:
    """Vue en direct sur une session (en fond). Renvoie « r » (retour, la protection
    continue) ou « q » (quitter : l'appelant arrête tout)."""
    screen = screen or LiveScreen()
    page = 0
    frames = 0
    try:
        screen.enter()
        while max_frames is None or frames < max_frames:
            frames += 1
            deadline = time.monotonic() + REFRESH_SECONDS
            while time.monotonic() < deadline and not kbhit():
                time.sleep(0.02)
            if not session.alive() and session.started:
                return "q"
            ctrl, rec_obj = session.ctrl, session.recorder
            rec = (
                recording_status(True, rec_obj.path)
                if rec_obj.active
                else recording_status(False)
            )
            cols, lines_ = shutil.get_terminal_size((120, 30))
            with session.lock:
                peers, now = list(session.peers), session.now
                try:
                    page = clamp_page(page, len(peers), lines_, ctrl, session.counter)
                    frame = render(
                        session.monitor,
                        ctrl,
                        peers,
                        rec,
                        now,
                        session.counter,
                        size=(cols, lines_),
                        page=page,
                    )
                    prompt_frame = render(
                        session.monitor,
                        ctrl,
                        peers,
                        rec,
                        now,
                        session.counter,
                        size=(cols, max(3, lines_ - 2)),
                        page=page,
                    )
                except Exception:
                    logger.exception("live : rendu impossible")
                    frame = prompt_frame = fit_line(t("live.render_error"), cols)
            screen.draw(frame)
            if not kbhit():
                continue
            key = read_key(getwch, kbhit)
            if key in ("q", "r"):
                return key
            nav = page_step(key)
            if nav:
                page += nav
                continue
            prompt = make_prompt(screen, prompt_frame, cols)
            try:
                handle_key(
                    key, ctrl, peers, session.blocked, rec_obj, prompt, session.config
                )
            except (EOFError, KeyboardInterrupt):
                raise
            except Exception:
                logger.exception("live : action %r impossible", key)
                ctrl.events.append(t("live.action_error", action=key.upper()))
        return "r"
    except KeyboardInterrupt:
        return "q"
    finally:
        screen.leave()


def _create_session() -> BackgroundSession:  # pragma: no cover - Windows uniquement
    from network.recorder import MetadataRecorder
    from network.sessions import extra_ports_enabled

    config = ConfigData()
    manager = Manager()
    blocked: MutableMapping[str, float] = manager.dict()
    total_blocked: MutableMapping[str, float] = manager.dict()
    total_flag = Value("b", 0)
    relay_flag = Value("b", 0)
    lock_flag = Value("b", 0)
    offender_flag = Value("b", 0)
    offender_ips: MutableMapping[str, float] = manager.dict()
    panic_flag = Value("b", 0)
    friends: MutableMapping[str, str] = manager.dict()
    friends.update(load_friends(config.data.get(FRIENDS_KEY)))
    packets: Queue[Packet] = Queue(QUEUE_MAX)
    from config.globallist import Whitelist
    from menu.menu import Menu  # import tardif : menu.py importe ce module
    from network import autoblock
    from network.incident import ReportWriter, build_report
    from network.offenders import OffenderStore

    monitor = SessionMonitor()
    player_counter = PlayerCounter()
    writer = ReportWriter()

    def reporter(ip: str, kind: str, pseudo: str) -> None:
        # Construit ici (données de anomaly.py), écrit dans le thread du ReportWriter.
        writer.submit(
            build_report(monitor.peers.get(ip), ip, kind, time.time(), pseudo)
        )

    guard = make_auto_block_guard(set(Whitelist().ips), Menu.dynamic_blacklist)
    ranges_ok = bool(Menu.dynamic_blacklist)
    saver = autoblock.AutoBlockSaver()
    ctrl = LiveSessionController(
        blocked,
        Blacklist(),
        auto_block=bool(config.data.get(AUTO_BLOCK_KEY, AUTO_BLOCK_DEFAULT)),
        auto_block_guard=guard,
        reporter=reporter,
        auto_block_available=ranges_ok,
        auto_store=saver,
        total_block=bool(config.data.get(TOTAL_BLOCK_KEY, TOTAL_BLOCK_DEFAULT)),
        total_blocked=total_blocked,
        total_flag=total_flag,
        relay_mode=normalize(config.data.get(RELAY_KEY, RELAY_DEFAULT)),
        relay_flag=relay_flag,
        session_lock=bool(config.data.get(SESSION_LOCK_KEY, SESSION_LOCK_DEFAULT)),
        lock_flag=lock_flag,
        offenders=OffenderStore(guard=is_rockstar_server),
        offender_ips=offender_ips,
        offender_sound=bool(
            config.data.get(OFFENDER_SOUND_KEY, OFFENDER_SOUND_DEFAULT)
        ),
        offender_drop=bool(config.data.get(OFFENDER_DROP_KEY, OFFENDER_DROP_DEFAULT)),
        offender_flag=offender_flag,
        friends=friends,
        panic_flag=panic_flag,
        # Lecture une seule fois, avant le démarrage de la capture.
        auto_entries=autoblock.load(time.time(), guard, max_seconds=AUTO_BLOCK_SECONDS)
        if ranges_ok
        else {},
    )
    if ranges_ok:
        saver.request(ctrl.auto_entries)  # réécrit le fichier purgé/filtré
    proc = Process(
        target=capture_loop,
        args=(
            blocked,
            packets,
            extra_ports_enabled(),
            total_blocked,
            total_flag,
            relay_flag,
            lock_flag,
            offender_flag,
            offender_ips,
            panic_flag,
            friends,
        ),
        daemon=True,
    )
    return BackgroundSession(
        proc,
        packets,
        ctrl,
        monitor,
        player_counter,
        MetadataRecorder(),
        # closers[0] avant l'arrêt de la capture, les suivants après.
        closers=[writer.close, saver.close, manager.shutdown],
        config=config,
        blocked=blocked,
        new_players=make_new_player_tracker(),
    )


def make_new_player_tracker() -> Any:
    """Tracker nouveau joueur avec journal sous %LOCALAPPDATA%\\Guardian\\journal."""
    from network.newplayer import NewPlayerTracker, PlayerJournal

    return NewPlayerTracker(
        is_rockstar_server,
        PlayerJournal(),
        alert=lambda ip, cc: t("live.ev.new_player", ip=ip, country=cc),
    )


def run_live_session() -> None:  # pragma: no cover - interactif, Windows uniquement
    """Point d'entrée du menu principal : réattache la session en fond si elle tourne."""
    if sys.platform != "win32":
        print(t("live.windows_only"))
        return
    import msvcrt

    session = attach_or_start(_create_session)
    try:
        result = live_view(session, msvcrt.getwch, msvcrt.kbhit)
    except BaseException:
        stop_background()
        raise
    if result == "q":
        stop_background()
