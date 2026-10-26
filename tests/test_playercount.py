"""Compteur de joueurs en direct (vue « Session en direct »)."""

import logging

from guardian.menu import livesession as ls
from guardian.network.anomaly import SessionMonitor
from guardian.util import i18n

A, B, C, D = "203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"


class Mono:
    def __init__(self, now=500.0):
        self.now = now

    def __call__(self):
        return self.now


class FakeList(dict):
    def __iter__(self):
        return iter(self.items())

    def add(self, ip, name):
        self[ip] = name

    def remove(self, ip):
        del self[ip]


def ctrl(total=True):
    return ls.LiveSessionController(
        {}, FakeList(), clock=lambda: 1000.0, total_block=total
    )


def test_constants():
    assert ls.PLAYER_TIMEOUT_SECONDS == 60.0
    assert ls.MAX_PLAYERS > 0
    import time

    assert ls.PlayerCounter().clock is time.monotonic


def test_counts_distinct_ips():
    c = ls.PlayerCounter(clock=Mono())
    for ip in (A, B, A, C, A):
        c.seen(ip)
    assert sorted(c.players()) == [A, B, C]
    assert c.counts(ctrl()) == (3, 3, 0, 0)


def test_expiry_after_timeout():
    clock = Mono(500.0)
    c = ls.PlayerCounter(clock=clock)
    c.seen(A)
    clock.now = 530.0
    c.seen(B)
    clock.now = 559.9
    assert sorted(c.players()) == [A, B]
    clock.now = 560.0  # A inactif depuis 60 s
    assert c.players() == [B]
    clock.now = 600.0
    c.seen(B)  # activité : B reste
    clock.now = 659.0
    assert c.players() == [B]
    clock.now = 660.0
    assert c.players() == [] and c.last_seen == {}  # purgé


def test_three_states():
    k = ctrl(total=True)
    k.blocked[A] = ls.PERMANENT  # Blacklist
    k.blocked[B] = 5000.0  # blocage auto (non expiré)
    k.blocked[C] = 1000.0 + 600  # bloqué ET coupé -> compté bloqué
    k.total_blocked[D] = 1000.0 + 600  # coupure sortante seule
    counter = ls.PlayerCounter(clock=Mono())
    for ip in (A, B, C, D, "203.0.113.9"):
        counter.seen(ip)
    assert counter.counts(k) == (5, 1, 3, 1)
    k.blocked[B] = 999.0  # blocage auto expiré -> normal
    assert counter.counts(k) == (5, 2, 2, 1)


def test_cut_only_when_total_block_on_and_not_expired():
    k = ctrl(total=True)
    k.total_blocked[D] = 999.0  # coupure expirée
    counter = ls.PlayerCounter(clock=Mono())
    counter.seen(D)
    assert counter.counts(k) == (1, 1, 0, 0)


def test_memory_bound():
    clock = Mono()
    c = ls.PlayerCounter(max_players=3, clock=clock)
    for i in range(10):
        clock.now += 1
        c.seen(f"198.51.100.{i}")
    assert len(c.last_seen) == 3
    assert list(c.last_seen) == [f"198.51.100.{i}" for i in (7, 8, 9)]
    c.seen("198.51.100.7")  # rafraîchi : passe en dernier
    c.seen("198.51.100.42")
    assert list(c.last_seen) == ["198.51.100.9", "198.51.100.7", "198.51.100.42"]


def test_no_full_ip_in_logs(caplog):
    k = ctrl()
    k.blocked[A] = ls.PERMANENT
    with caplog.at_level(logging.DEBUG):
        c = ls.PlayerCounter(max_players=2, clock=Mono())
        for ip in (A, B, C, D):
            c.seen(ip)
        c.counts(k)
        ls.players_line(c, k)
    text = caplog.text + " ".join(str(r.args) for r in caplog.records)
    for ip in (A, B, C, D):
        assert ip not in text


def test_texts_fr_en():
    s = i18n.STRINGS["live.players"]
    assert s["fr"].format(n=7, normal=5, blocked=1, cut=1) == (
        "Joueurs : 7 (normaux 5, bloqués 1, coupés 1)"
    )
    assert s["en"].format(n=7, normal=5, blocked=1, cut=1) == (
        "Players: 7 (normal 5, blocked 1, cut 1)"
    )


def test_render_shows_players_line():
    k = ctrl()
    c = ls.PlayerCounter(clock=Mono())
    c.seen(A)
    out = ls.render(SessionMonitor(), k, [], "off", 0.0, c)
    assert "Joueurs : 1 (normaux 1, bloqués 0, coupés 0)" in out
    assert "Joueurs" not in ls.render(SessionMonitor(), k, [], "off", 0.0)


def test_capture_loop_untouched_and_metadata_only():
    import inspect

    src = inspect.getsource(ls.capture_loop)
    assert "PlayerCounter" not in src and "player" not in src
    pc = inspect.getsource(ls.PlayerCounter)
    assert "payload" not in pc and ".send(" not in pc
    run = inspect.getsource(ls.run_live_session)
    assert "player_counter.seen(ip)" in run
    assert "render(monitor, ctrl, peers, rec, now, player_counter)" in run
