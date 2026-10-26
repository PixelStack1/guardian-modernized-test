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
import os
import queue
import sys
import time
from collections.abc import Callable, MutableMapping
from datetime import datetime
from multiprocessing import Manager, Process, Queue
from typing import Any

from colorama import Fore, Style

from config.configdata import ConfigData
from config.globallist import Blacklist
from network.anomaly import LEVEL_KEYS, Level, PeerState, SessionMonitor
from util.geoip import country_label
from util.i18n import t

# Priorité WinDivert du handle de la vue en direct (plus haute = vu en premier).
LIVE_PRIORITY = 1000
# Durée d'un blocage automatique (secondes).
AUTO_BLOCK_SECONDS = 10 * 60
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

Packet = tuple[float, str, int, bool]  # (horodatage, ip du pair, taille, entrant)


def is_blocked(blocked: MutableMapping[str, float], ip: str, now: float) -> bool:
    """``blocked`` : ip -> expiration (epoch) ; PERMANENT = jamais."""
    expiry = blocked.get(ip)
    if expiry is None:
        return False
    return expiry == PERMANENT or now < expiry


def capture_loop(
    blocked: MutableMapping[str, float],
    out: Queue[Packet],
    extra_ports: bool,
) -> None:  # pragma: no cover - nécessite Windows + WinDivert
    from network.sessions import open_windivert, packet_filter

    with (
        contextlib.suppress(KeyboardInterrupt),
        open_windivert(priority=LIVE_PRIORITY, filter_=packet_filter(extra_ports)) as w,
    ):
        # Copie locale de la liste partagée, rafraîchie toutes les BLOCKLIST_REFRESH s :
        # évite un aller-retour inter-processus par paquet (latence en jeu).
        local: dict[str, float] = dict(blocked)
        next_refresh = 0.0
        for packet in w:
            inbound = bool(packet.is_inbound)
            ip = packet.ip.src_addr if inbound else packet.ip.dst_addr
            now = time.time()
            if now >= next_refresh:
                local = dict(blocked)
                next_refresh = now + BLOCKLIST_REFRESH
            if not (inbound and is_blocked(local, ip, now)):
                w.send(packet)
            with contextlib.suppress(queue.Full):
                out.put_nowait((now, ip, len(packet.payload), inbound))


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
    ) -> None:
        self.blocked = blocked
        # Concerne UNIQUEMENT le blocage automatique ; le blocage manuel (B) peut
        # bloquer n'importe quelle IP choisie par l'utilisateur.
        self.auto_block_guard = auto_block_guard or (lambda _ip: False)
        self._guard_reported: set[str] = set()
        self.blacklist = blacklist
        self.auto_block = auto_block
        self.clock = clock
        self.pseudos: dict[str, str] = {}
        self.events: list[str] = []
        # Les IP déjà en Blacklist restent bloquées dans cette vue aussi.
        for ip, _name in list(blacklist):
            self.blocked[ip] = PERMANENT

    def block(self, ip: str, pseudo: str = "") -> None:
        """Blocage MANUEL immédiat, écrit de façon PERMANENTE dans la Blacklist
        (data.json). À l'inverse, le bouclier auto ne bloque qu'en mémoire, 10 min."""
        pseudo = pseudo or self.pseudos.get(ip, "")
        self.blocked[ip] = PERMANENT
        self.blacklist.add(ip, blacklist_label(pseudo, datetime.now()))
        self.blacklist.save()
        self.events.append(t("live.ev.blocked", ip=ip))

    def auto_block_if_needed(self, peer: PeerState) -> bool:
        if not self.auto_block or peer.level < Level.SUSPECT:
            return False
        if peer.ip in self.blocked:
            return False
        if self.auto_block_guard(peer.ip):
            if peer.ip not in self._guard_reported:
                self._guard_reported.add(peer.ip)
                self.events.append(t("live.ev.auto_skipped", ip=peer.ip))
            return False
        # Blocage en mémoire uniquement (jamais écrit dans data.json), expire seul.
        self.blocked[peer.ip] = self.clock() + AUTO_BLOCK_SECONDS
        self.events.append(
            t(
                "live.ev.auto",
                ip=peer.ip,
                reason=t(peer.reason_key or "reason.burst"),
                minutes=AUTO_BLOCK_SECONDS // 60,
            )
        )
        return True

    def unblock(self, ip: str, remove_from_blacklist: bool = True) -> None:
        self.blocked.pop(ip, None)
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

    def block_status(self, ip: str) -> str:
        expiry = self.blocked.get(ip)
        if expiry is None:
            return ""
        if expiry == PERMANENT:
            return t("live.blocked")
        return t("live.blocked_min", m=max(0, int(expiry - self.clock())) // 60 + 1)


LEVEL_COLORS = {
    Level.NORMAL: "",
    Level.INHABITUEL: Fore.YELLOW,  # orange (pas d'orange en ANSI 16 couleurs)
    Level.SUSPECT: Fore.LIGHTRED_EX,
}


def render(
    monitor: SessionMonitor,
    ctrl: LiveSessionController,
    peers: list[PeerState],
    recording: str,
    now: float,
) -> str:
    lines = [
        Style.BRIGHT + t("live.title") + Style.RESET_ALL,
        t(
            "live.status",
            minutes=AUTO_BLOCK_SECONDS // 60,
            auto=t("live.on") if ctrl.auto_block else t("live.off"),
            hint="" if ctrl.auto_block else t("live.auto_hint"),
            rec=recording,
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
    alerts = []
    for i, p in enumerate(peers, 1):
        s = p.window.stats(now)
        state = ctrl.block_status(p.ip) or (
            t("level.learning") if p.learning(now) else t(LEVEL_KEYS[Level(p.level)])
        )
        first = datetime.fromtimestamp(p.first_seen).strftime("%H:%M:%S")
        row = (
            f"{i:>2}  {p.ip:<15}  {country_label(p.ip):<5}  {first:<10}  "
            f"{s.pps:>6.0f}  {s.bps:>8.0f}  {s.avg_size:>5.0f}  {s.max_size:>5}  "
            f"{state:<10}  {ctrl.pseudos.get(p.ip, '')}"
        )
        color = LEVEL_COLORS[p.level]
        lines.append(color + row + Style.RESET_ALL if color else row)
        if p.alert:
            alerts.append(color + p.alert + Style.RESET_ALL)
    if not peers:
        lines.append(t("live.no_peers"))
    lines += ["", *alerts, *ctrl.events[-5:], ""]
    lines.append(t("live.keys"))
    return "\n".join(lines)


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
    packets: Queue[Packet] = Queue(QUEUE_MAX)
    from config.globallist import Whitelist
    from menu.menu import Menu  # import tardif : menu.py importe ce module

    ctrl = LiveSessionController(
        blocked,
        Blacklist(),
        auto_block=bool(config.data.get(AUTO_BLOCK_KEY, AUTO_BLOCK_DEFAULT)),
        auto_block_guard=make_auto_block_guard(
            set(Whitelist().ips), Menu.dynamic_blacklist
        ),
    )
    monitor = SessionMonitor()
    recorder = MetadataRecorder()
    proc = Process(
        target=capture_loop, args=(blocked, packets, extra_ports_enabled()), daemon=True
    )
    proc.start()
    try:
        while True:
            deadline = time.monotonic() + REFRESH_SECONDS
            next_eval = time.monotonic() + EVAL_SECONDS
            peers: list[PeerState] = []
            while True:
                try:
                    ts, ip, size, inbound = packets.get(timeout=0.02)
                    recorder.write(ts, ip, size, inbound)
                    if inbound:
                        monitor.add_packet(ip, size, ts)
                except queue.Empty:
                    pass
                if time.monotonic() >= next_eval:
                    # Bouclier auto évalué toutes les EVAL_SECONDS, pas seulement à l'affichage.
                    next_eval = time.monotonic() + EVAL_SECONDS
                    now = time.time()
                    ctrl.expire()
                    peers = monitor.evaluate(now)
                    for p in peers:
                        ctrl.auto_block_if_needed(p)
                    if time.monotonic() >= deadline:
                        break
            monitor.prune(now)
            rec = (
                t("live.rec_on", path=recorder.path)
                if recorder.active
                else t("live.off")
            )
            os.system("cls")
            print(render(monitor, ctrl, peers, rec, now))

            if not msvcrt.kbhit():
                continue
            key = msvcrt.getwch().lower()
            if key == "q":
                break
            if key == "b":
                peer = _ask_row(peers, t("live.ask_block"))
                if peer:
                    pseudo = input(t("live.ask_pseudo"))
                    ctrl.block(peer.ip, pseudo)
            elif key == "p":
                peer = _ask_row(peers, t("live.ask_row"))
                if peer:
                    ctrl.pseudos[peer.ip] = input(
                        t("live.ask_pseudo_for", ip=peer.ip)
                    ).strip()
            elif key == "d":
                ips = list(blocked.keys())
                for i, ip in enumerate(ips, 1):
                    print(f"{i:>2}  {ip}  {ctrl.block_status(ip)}")
                answer = input(t("live.ask_unblock")).strip()
                if answer.isdigit() and 1 <= int(answer) <= len(ips):
                    ctrl.unblock(ips[int(answer) - 1])
            elif key == "a":
                ctrl.auto_block = not ctrl.auto_block
            elif key == "e":
                if recorder.active:
                    recorder.stop()
                else:
                    recorder.start()
    except KeyboardInterrupt:
        pass
    finally:
        recorder.stop()
        proc.terminate()
        proc.join(timeout=5)
        manager.shutdown()
