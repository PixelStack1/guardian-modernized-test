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

import contextlib
import logging
import queue
import re
import shutil
import sys
import time
from collections.abc import Callable, MutableMapping
from datetime import UTC, datetime
from multiprocessing import Manager, Process, Queue, Value
from typing import Any

from colorama import Fore, Style

from config.configdata import ConfigData
from config.globallist import Blacklist
from network.anomaly import LEVEL_KEYS, Level, PeerState, SessionMonitor
from util.geoip import country_code
from util.i18n import t

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
) -> bool:
    """Décision par paquet (aucune modification, aucune création de paquet).

    Entrant : rejeté si la source est bloquée. Sortant : rejeté UNIQUEMENT si la
    destination exacte est en coupure sortante (mode blocage total) et toujours
    bloquée en entrant. En cas d'erreur, le paquet passe (fail-safe)."""
    try:
        if inbound:
            return is_blocked(blocked, src, now)
        if not total_on:  # mode blocage total OFF : aucun sortant n'est jeté
            return False
        expiry = total.get(dst)
        return expiry is not None and now < expiry and is_blocked(blocked, dst, now)
    except Exception:
        return False


def handle_packet(
    w: Any,
    packet: Any,
    blocked: MutableMapping[str, float],
    total: MutableMapping[str, float],
    now: float,
    total_on: bool = True,
) -> bool:
    """Réinjecte le paquet ORIGINAL tel quel (``w.send(packet)``) ou le jette.
    Renvoie True si envoyé. Jamais de paquet fabriqué ni modifié."""
    try:
        inbound = bool(packet.is_inbound)
        outbound = bool(packet.is_outbound)
        drop = (inbound or outbound) and should_drop(
            inbound,
            packet.ip.src_addr,
            packet.ip.dst_addr,
            blocked,
            total,
            now,
            total_on,
        )
    except Exception:
        drop = False
    if drop:
        return False
    w.send(packet)
    return True


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
        next_refresh = 0.0
        for packet in w:
            inbound = bool(packet.is_inbound)
            ip = packet.ip.src_addr if inbound else packet.ip.dst_addr
            now = time.time()
            if now >= next_refresh:
                local = dict(blocked)
                local_total = dict(total_blocked) if total_blocked is not None else {}
                total_on = read_flag(total_flag)
                next_refresh = now + BLOCKLIST_REFRESH
            handle_packet(w, packet, local, local_total, now, total_on)
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


def note_player(counter: PlayerCounter, ip: str, inbound: bool) -> None:
    """Anti-usurpation : seul un paquet ENTRANT compte (IP du pair = source).
    Une destination sortante (arbitraire) n'est jamais comptée."""
    if inbound:
        counter.seen(ip)


def players_line(counter: PlayerCounter, ctrl: LiveSessionController) -> str:
    total, normal, blocked, cut = counter.counts(ctrl)
    n = (
        t("live.players_full", max=counter.max_players)
        if counter.saturated()
        else str(total)
    )
    return t("live.players", n=n, normal=normal, blocked=blocked, cut=cut)


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
    ) -> None:
        self.blocked = blocked
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

    def toggle_total_block(self) -> None:
        self.total_block = self.auto_block_available and not self.total_block

    def _persist(self) -> None:
        if self.auto_store is not None:
            with contextlib.suppress(Exception):
                self.auto_store.request(self.auto_entries)

    def block(self, ip: str, pseudo: str = "") -> None:
        """Blocage MANUEL immédiat, écrit de façon PERMANENTE dans la Blacklist
        (data.json). Le bouclier auto, lui, bloque 7 jours via auto_block.json."""
        pseudo = pseudo or self.pseudos.get(ip, "")
        self.blocked[ip] = PERMANENT
        if self.auto_entries.pop(ip, None) is not None:  # devient permanent (data.json)
            self._persist()
        self.blacklist.add(ip, blacklist_label(pseudo, datetime.now()))
        self.blacklist.save()
        self.events.append(t("live.ev.blocked", ip=ip))
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
        ):
            return False
        if peer.ip in self.blocked:
            return False
        if self.auto_block_guard(peer.ip):
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


def render_head(
    ctrl: LiveSessionController, recording: str, players: PlayerCounter | None = None
) -> list[str]:
    return [
        Style.BRIGHT + t("live.title") + Style.RESET_ALL,
        *([players_line(players, ctrl)] if players is not None else []),
        t(
            "live.status",
            days=AUTO_BLOCK_SECONDS // 86400,
            auto=t("live.on") if ctrl.auto_block else t("live.off"),
            hint="" if ctrl.auto_block else t("live.auto_hint"),
            rec=recording,
        ),
        t(
            "live.total_status",
            minutes=TOTAL_BLOCK_SECONDS // 60,
            state=t("live.on") if ctrl.total_block else t("live.off"),
        ),
        t("live.total_warning"),
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
        state = ctrl.block_status(p.ip) or (
            t("level.learning") if p.learning(now) else t(LEVEL_KEYS[Level(p.level)])
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
            f"{i:>2}  {p.ip:<15}  {(country_code(p.ip) or '—'):<5}  {first:<10}  "
            f"{s.pps:>6.0f}  {s.bps:>8.0f}  {s.avg_size:>5.0f}  {s.max_size:>5}  "
            f"{state:<10}  {ctrl.pseudos.get(p.ip, '')}"
        )
        color = LEVEL_COLORS[p.level]
        rows.append(color + row + Style.RESET_ALL if color else row)
        if p.alert:
            alerts.append(color + p.alert + Style.RESET_ALL)
    if not peers:
        rows.append(t("live.no_peers"))
    tail = ["", *alerts, *ctrl.events[-5:], "", t("live.keys")]
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
        if peer:
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
        ctrl.events.append(
            t(
                "live.ev.auto_toggled",
                state=t("live.on") if ctrl.auto_block else t("live.off"),
            )
        )
    elif key == "t":
        ctrl.toggle_total_block()
        _save(config, TOTAL_BLOCK_KEY, ctrl.total_block)
        ctrl.events.append(
            t(
                "live.ev.total_toggled",
                state=t("live.on") if ctrl.total_block else t("live.off"),
            )
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


def run_live_session() -> None:  # pragma: no cover - interactif, Windows uniquement
    """Point d'entrée du menu principal."""
    if sys.platform != "win32":
        print(t("live.windows_only"))
        return
    import msvcrt

    from network.recorder import MetadataRecorder
    from network.sessions import extra_ports_enabled

    config = ConfigData()
    manager = Manager()
    blocked: MutableMapping[str, float] = manager.dict()
    total_blocked: MutableMapping[str, float] = manager.dict()
    total_flag = Value("b", 0)
    packets: Queue[Packet] = Queue(QUEUE_MAX)
    from config.globallist import Whitelist
    from menu.menu import Menu  # import tardif : menu.py importe ce module
    from network import autoblock
    from network.incident import ReportWriter, build_report

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
        # Lecture une seule fois, avant le démarrage de la capture.
        auto_entries=autoblock.load(time.time(), guard, max_seconds=AUTO_BLOCK_SECONDS)
        if ranges_ok
        else {},
    )
    if ranges_ok:
        saver.request(ctrl.auto_entries)  # réécrit le fichier purgé/filtré
    recorder = MetadataRecorder()
    proc = Process(
        target=capture_loop,
        args=(blocked, packets, extra_ports_enabled(), total_blocked, total_flag),
        daemon=True,
    )
    proc.start()
    screen = LiveScreen()
    page = 0
    redraw_now = False
    try:
        screen.enter()
        while True:
            deadline = time.monotonic() + (0.0 if redraw_now else REFRESH_SECONDS)
            redraw_now = False
            next_eval = time.monotonic()
            peers: list[PeerState] = []
            while True:
                try:
                    ts, ip, size, inbound, port = packets.get(timeout=0.02)
                    recorder.write(ts, ip, size, inbound)
                    note_player(player_counter, ip, inbound)
                    if inbound:
                        monitor.add_packet(ip, size, ts, port)
                except queue.Empty:
                    pass
                if time.monotonic() >= next_eval:
                    # Bouclier auto évalué toutes les EVAL_SECONDS, pas seulement à l'affichage.
                    next_eval = time.monotonic() + EVAL_SECONDS
                    now = time.time()
                    ctrl.expire()
                    peers = monitor.evaluate(now)
                    for p in peers:
                        try:
                            ctrl.auto_block_if_needed(p)
                        except Exception:
                            logger.exception("bouclier auto : évaluation impossible")
                    if time.monotonic() >= deadline:
                        break
                if msvcrt.kbhit():
                    break  # réaction immédiate à une touche
            monitor.prune(now)
            rec = (
                t("live.rec_on", path=recorder.path)
                if recorder.active
                else t("live.off")
            )
            cols, lines_ = shutil.get_terminal_size((120, 30))
            frame_size = (cols, lines_)
            try:
                page = clamp_page(page, len(peers), lines_, ctrl, player_counter)
                screen.draw(
                    render(
                        monitor,
                        ctrl,
                        peers,
                        rec,
                        now,
                        player_counter,
                        size=frame_size,
                        page=page,
                    )
                )
            except Exception:
                # Ne jamais laisser l'écran noir : on journalise et on continue.
                logger.exception("live : rendu impossible")
                screen.draw(fit_line(t("live.render_error"), cols))

            if not msvcrt.kbhit():
                continue
            key = read_key(msvcrt.getwch, msvcrt.kbhit)
            if key == "q":
                break
            redraw_now = True
            nav = page_step(key)
            if nav:
                page += nav
                continue

            prompt_frame = render(
                monitor,
                ctrl,
                peers,
                rec,
                now,
                player_counter,
                size=(cols, max(3, lines_ - 2)),
                page=page,
            )
            prompt = make_prompt(screen, prompt_frame, cols)

            try:
                handle_key(key, ctrl, peers, blocked, recorder, prompt, config)
            except (EOFError, KeyboardInterrupt):
                raise
            except Exception:
                logger.exception("live : action %r impossible", key)
                ctrl.events.append(t("live.action_error", action=key.upper()))
    except KeyboardInterrupt:
        pass
    finally:
        screen.leave()
        recorder.stop()
        writer.close()
        saver.close()
        proc.terminate()
        proc.join(timeout=5)
        manager.shutdown()
