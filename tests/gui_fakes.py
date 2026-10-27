"""Session factice (sans WinDivert) pour les tests GUI et les captures d'écran."""

from __future__ import annotations

import queue
import time

from menu import livesession as ls
from network.anomaly import SessionMonitor
from network.blackbox import BlackBox
from network.filters import PING_IDLE, PING_MIN_SAMPLES
from network.newplayer import NewPlayerTracker
from network.offenders import OffenderStore


class FakeList(dict):
    def __iter__(self):
        return iter(self.items())

    def add(self, ip, name):
        self[ip] = name

    def remove(self, ip):
        del self[ip]

    def save(self):
        pass


class FakeConfig:
    def __init__(self, data=None):
        self.data = dict(data or {})
        self.saves = 0

    def save(self):
        self.saves += 1


class FakeRecorder:
    active = False
    path = "enregistrement.csv"

    def start(self):
        self.active = True

    def stop(self):
        self.active = False

    def write(self, *_a):
        pass


class FakeProc:
    def start(self):
        pass

    def is_alive(self):
        return True

    def terminate(self):
        pass

    def join(self, timeout=None):
        pass


DEMO_PEERS = [
    ("203.0.113.10", 18, 28),
    ("203.0.113.22", 24, 41),
    ("198.51.100.17", 105, 52),
    ("198.51.100.89", 15, 36),
    ("203.0.113.110", 22, 48),
    ("192.0.2.160", 47, 33),
    ("192.0.2.12", 12, 98),
    ("198.51.100.23", 68, 142),
]


def make_session(tmp_path=None, config=None):
    cfg = config if config is not None else FakeConfig({"language": "fr"})
    offenders = OffenderStore(persist=False, guard=ls.is_rockstar_server)
    ctrl = ls.LiveSessionController(
        {},
        FakeList(),
        auto_block=True,
        auto_block_available=True,
        offenders=offenders,
        filters=ls.make_filters(cfg.data),
        sound=lambda: None,
    )
    s = ls.BackgroundSession(
        FakeProc(),
        queue.Queue(),
        ctrl,
        SessionMonitor(),
        ls.PlayerCounter(),
        FakeRecorder(),
        config=cfg,
        new_players=NewPlayerTracker(ls.is_rockstar_server, None),
        blackbox=BlackBox(directory=tmp_path, seconds=30, threaded=False),
    )
    return s


def feed(session, peers=DEMO_PEERS, seconds=3.0):
    """Paquets factices (métadonnées seules) passés par le vrai chemin step()."""
    now = time.time()
    gap = PING_IDLE + 0.2
    rounds = PING_MIN_SAMPLES + 2
    for ip, pps, ping in peers:
        start = now - seconds - rounds * gap - 1.0
        for j in range(rounds):
            t_in = start + j * gap
            t_out = t_in + PING_IDLE + 0.01
            session.packets.put((t_in, ip, 120, True, 6672))
            session.packets.put((t_out, ip, 80, False, 6672))
            session.packets.put((t_out + ping / 1000.0, ip, 120, True, 6672))
        n = int(pps * seconds)
        for k in range(n):
            ts = now - seconds + k / pps
            session.packets.put((ts - 0.03, ip, 80, False, 6672))
            session.packets.put((ts, ip, 120, True, 6672))
    while not session.packets.empty():
        session.step(timeout=0)
    session.evaluate()
