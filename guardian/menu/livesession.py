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
from network.anomaly import Level, PeerState, SessionMonitor

# Priorité WinDivert du handle de la vue en direct (plus haute = vu en premier).
LIVE_PRIORITY = 1000
# Durée d'un blocage automatique (secondes).
AUTO_BLOCK_SECONDS = 10 * 60
# Clé de data.json pour activer l'auto-blocage des IP rouges (désactivé par défaut).
AUTO_BLOCK_KEY = "auto_block_suspect"
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
        for packet in w:
            inbound = bool(packet.is_inbound)
            ip = packet.ip.src_addr if inbound else packet.ip.dst_addr
            now = time.time()
            if not (inbound and is_blocked(blocked, ip, now)):
                w.send(packet)
            with contextlib.suppress(queue.Full):
                out.put_nowait((now, ip, len(packet.payload), inbound))


def blacklist_label(pseudo: str, when: datetime) -> str:
    """Nom enregistré dans la Blacklist : pseudo/note + date de blocage."""
    stamp = when.strftime("%Y-%m-%d %H:%M:%S")
    pseudo = pseudo.strip()
    return f"{pseudo} [bloqué le {stamp}]" if pseudo else f"Bloqué le {stamp}"


class LiveSessionController:
    """Logique de blocage/déblocage (testable sans console ni WinDivert)."""

    def __init__(
        self,
        blocked: MutableMapping[str, float],
        blacklist: Any,
        auto_block: bool = False,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.blocked = blocked
        self.blacklist = blacklist
        self.auto_block = auto_block
        self.clock = clock
        self.pseudos: dict[str, str] = {}
        self.events: list[str] = []
        # Les IP déjà en Blacklist restent bloquées dans cette vue aussi.
        for ip, _name in list(blacklist):
            self.blocked[ip] = PERMANENT

    def block(self, ip: str, pseudo: str = "") -> None:
        """Blocage immédiat + persistance dans la Blacklist existante."""
        pseudo = pseudo or self.pseudos.get(ip, "")
        self.blocked[ip] = PERMANENT
        self.blacklist.add(ip, blacklist_label(pseudo, datetime.now()))
        self.blacklist.save()
        self.events.append(f"IP {ip} bloquée et ajoutée à la Blacklist")

    def auto_block_if_needed(self, peer: PeerState) -> bool:
        if not self.auto_block or peer.level < Level.SUSPECT:
            return False
        if peer.ip in self.blocked:
            return False
        self.blocked[peer.ip] = self.clock() + AUTO_BLOCK_SECONDS
        self.events.append(
            f"IP {peer.ip} bloquée automatiquement pour {AUTO_BLOCK_SECONDS // 60} min"
        )
        return True

    def unblock(self, ip: str, remove_from_blacklist: bool = True) -> None:
        self.blocked.pop(ip, None)
        if remove_from_blacklist and ip in self.blacklist:
            self.blacklist.remove(ip)
            self.blacklist.save()
        self.events.append(f"IP {ip} débloquée")

    def expire(self) -> None:
        now = self.clock()
        for ip, expiry in list(self.blocked.items()):
            if expiry != PERMANENT and now >= expiry:
                self.blocked.pop(ip, None)
                self.events.append(f"Blocage automatique de {ip} expiré")

    def block_status(self, ip: str) -> str:
        expiry = self.blocked.get(ip)
        if expiry is None:
            return ""
        if expiry == PERMANENT:
            return "BLOQUÉE"
        return f"BLOQUÉE {max(0, int(expiry - self.clock())) // 60 + 1} min"


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
        Style.BRIGHT
        + "Guardian — Session en direct (version de test)"
        + Style.RESET_ALL,
        f"Auto-blocage (rouge, {AUTO_BLOCK_SECONDS // 60} min) : "
        f"{'ACTIVÉ' if ctrl.auto_block else 'désactivé'}   Enregistrement : {recording}",
        "",
        f"{'#':>2}  {'IP':<15}  {'Pays':<4}  {'Vu depuis':<9}  {'Paq/s':>6}  "
        f"{'Oct/s':>8}  {'Moy':>5}  {'Max':>5}  {'État':<10}  Pseudo",
    ]
    alerts = []
    for i, p in enumerate(peers, 1):
        s = p.window.stats(now)
        state = ctrl.block_status(p.ip) or (
            "apprent." if p.learning(now) else Level(p.level).name.lower()
        )
        first = datetime.fromtimestamp(p.first_seen).strftime("%H:%M:%S")
        row = (
            f"{i:>2}  {p.ip:<15}  {'':<4}  {first:<9}  {s.pps:>6.0f}  "
            f"{s.bps:>8.0f}  {s.avg_size:>5.0f}  {s.max_size:>5}  {state:<10}  "
            f"{ctrl.pseudos.get(p.ip, '')}"
        )
        color = LEVEL_COLORS[p.level]
        lines.append(color + row + Style.RESET_ALL if color else row)
        if p.alert:
            alerts.append(color + p.alert + Style.RESET_ALL)
    if not peers:
        lines.append("(aucun pair connecté)")
    lines += ["", *alerts, *ctrl.events[-5:], ""]
    lines.append(
        "[B] Bloquer  [P] Pseudo  [D] Débloquer  [A] Auto-blocage  "
        "[E] Enregistrement  [Q] Retour"
    )
    return "\n".join(lines)


def _ask_row(peers: list[PeerState], prompt: str) -> PeerState | None:
    answer = input(prompt).strip()
    if answer.isdigit() and 1 <= int(answer) <= len(peers):
        return peers[int(answer) - 1]
    return None


def run_live_session() -> None:  # pragma: no cover - interactif, Windows uniquement
    """Point d'entrée du menu principal."""
    if sys.platform != "win32":
        print("La vue Session en direct nécessite Windows.")
        return
    import msvcrt

    from network.recorder import MetadataRecorder
    from network.sessions import extra_ports_enabled

    config = ConfigData()
    manager = Manager()
    blocked: MutableMapping[str, float] = manager.dict()
    packets: Queue[Packet] = Queue(QUEUE_MAX)
    ctrl = LiveSessionController(
        blocked,
        Blacklist(),
        auto_block=bool(config.data.get(AUTO_BLOCK_KEY, False)),
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
            while time.monotonic() < deadline:
                try:
                    ts, ip, size, inbound = packets.get(timeout=0.05)
                except queue.Empty:
                    continue
                recorder.write(ts, ip, size, inbound)
                if inbound:
                    monitor.add_packet(ip, size, ts)
            now = time.time()
            ctrl.expire()
            peers = monitor.evaluate(now)
            for p in peers:
                ctrl.auto_block_if_needed(p)
            monitor.prune(now)
            rec = f"ON ({recorder.path})" if recorder.active else "désactivé"
            os.system("cls")
            print(render(monitor, ctrl, peers, rec, now))

            if not msvcrt.kbhit():
                continue
            key = msvcrt.getwch().lower()
            if key == "q":
                break
            if key == "b":
                peer = _ask_row(peers, "Numéro de la ligne à bloquer : ")
                if peer:
                    pseudo = input("Pseudo / note (optionnel) : ")
                    ctrl.block(peer.ip, pseudo)
            elif key == "p":
                peer = _ask_row(peers, "Numéro de la ligne : ")
                if peer:
                    ctrl.pseudos[peer.ip] = input(f"Pseudo pour {peer.ip} : ").strip()
            elif key == "d":
                ips = list(blocked.keys())
                for i, ip in enumerate(ips, 1):
                    print(f"{i:>2}  {ip}  {ctrl.block_status(ip)}")
                answer = input("Numéro de l'IP à débloquer : ").strip()
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
