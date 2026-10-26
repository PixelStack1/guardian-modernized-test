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


def _func(name):
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(ls))
    return next(
        n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name
    )


def _names(node):
    import ast

    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)} | {
        n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)
    }


def test_capture_loop_untouched_and_metadata_only():
    import ast

    names = _names(_func("capture_loop"))
    assert not {"PlayerCounter", "note_player", "player_counter", "seen"} & names
    pc_names = _names(
        next(
            n
            for n in ast.walk(ast.parse(__import__("inspect").getsource(ls)))
            if isinstance(n, ast.ClassDef) and n.name == "PlayerCounter"
        )
    )
    assert not {"payload", "send", "WinDivert"} & pc_names


def test_display_loop_feeds_counter_with_direction_and_renders_it():
    import ast

    run = _func("run_live_session")
    feeds = [
        c
        for c in ast.walk(run)
        if isinstance(c, ast.Call)
        and isinstance(c.func, ast.Name)
        and c.func.id == "note_player"
    ]
    assert len(feeds) == 1
    assert [a.id for a in feeds[0].args] == ["player_counter", "ip", "inbound"]
    assert "seen" not in _names(run)  # jamais d'appel direct sans direction
    renders = [
        c
        for c in ast.walk(run)
        if isinstance(c, ast.Call)
        and isinstance(c.func, ast.Name)
        and c.func.id == "render"
    ]
    assert renders and all(
        any(isinstance(a, ast.Name) and a.id == "player_counter" for a in c.args)
        for c in renders
    )


def test_spoofed_outbound_ips_not_counted():
    c = ls.PlayerCounter(clock=Mono())
    for i in range(50):
        ls.note_player(c, f"198.51.100.{i}", inbound=False)  # destinations arbitraires
    assert c.players() == []
    ls.note_player(c, A, inbound=True)
    ls.note_player(c, B, inbound=False)
    assert c.players() == [A]


def test_saturated_display_fr_en():
    c = ls.PlayerCounter(clock=Mono())
    for i in range(ls.MAX_PLAYERS + 5):
        c.seen(f"10.{i // 65536}.{i // 256 % 256}.{i % 256}")
    k = ctrl()
    import sys

    rt = sys.modules[ls.t.__module__]  # module i18n réellement utilisé par ls
    rt.set_language("fr", persist=False)
    try:
        assert ls.players_line(c, k).startswith("Joueurs : ≥1024 (normaux 1024")
        rt.set_language("en", persist=False)
        assert ls.players_line(c, k).startswith("Players: ≥1024 (normal 1024")
    finally:
        rt.set_language("fr", persist=False)
    small = ls.PlayerCounter(clock=Mono())
    small.seen(A)
    assert ls.players_line(small, k).startswith("Joueurs : 1 (")


class CountingProxy:
    """Simule un DictProxy (Manager) en comptant les allers-retours."""

    def __init__(self, data):
        self.data = data
        self.calls = 0

    def keys(self):
        self.calls += 1
        return list(self.data)

    def __getitem__(self, k):
        return self.data[k]

    def get(self, *a):
        self.calls += 1
        return self.data.get(*a)

    def __contains__(self, k):
        self.calls += 1
        return k in self.data

    def __iter__(self):
        self.calls += 1
        return iter(self.data)


def test_single_manager_access_per_render():
    k = ctrl(total=True)
    k.blocked = CountingProxy({A: ls.PERMANENT})
    k.total_blocked = CountingProxy({B: 1600.0})
    c = ls.PlayerCounter(clock=Mono())
    for ip in (A, B, C, D, "203.0.113.9", "203.0.113.10"):
        c.seen(ip)
    out = ls.render(SessionMonitor(), k, [], "off", 0.0, c)
    assert "Joueurs : 6 (normaux 4, bloqués 1, coupés 1)" in out
    assert k.blocked.calls == 1 and k.total_blocked.calls == 1


def test_broken_proxy_is_safe():
    class Broken:
        def keys(self):
            raise EOFError

    k = ctrl(total=True)
    k.blocked = Broken()
    k.total_blocked = Broken()
    c = ls.PlayerCounter(clock=Mono())
    c.seen(A)
    assert c.counts(k) == (1, 1, 0, 0)


def test_saturation_logged_once_and_rearmed(caplog):
    clock = Mono()
    c = ls.PlayerCounter(max_players=3, timeout=60, clock=clock)
    with caplog.at_level(logging.DEBUG, logger=ls.logger.name):
        for i in range(20):
            c.seen(f"198.51.100.{i}")
    recs = [r for r in caplog.records if "satur" in r.getMessage()]
    assert len(recs) == 1 and recs[0].levelno == logging.DEBUG
    assert "198.51.100" not in caplog.text
    clock.now += 61
    c.purge()  # repasse sous la borne : drapeau réarmé
    assert not c.full
    caplog.clear()
    with caplog.at_level(logging.DEBUG, logger=ls.logger.name):
        for i in range(5):
            c.seen(f"192.0.2.{i}")
    assert len([r for r in caplog.records if "satur" in r.getMessage()]) == 1


def test_seen_is_constant_time_operations():
    """seen() ne parcourt jamais le dict (O(1)) : pas d'itération complète."""

    class Tracking(dict):
        iters = 0

        def __iter__(self):
            Tracking.iters += 1
            return super().__iter__()

    c = ls.PlayerCounter(max_players=4, clock=Mono())
    c.last_seen = Tracking()
    for i in range(100):
        c.seen(f"198.51.100.{i}")
    assert Tracking.iters <= 96  # exactement un next(iter()) par éviction (100 - 4)


def test_total_block_read_error_defaults_to_off():
    class Ctrl:
        blocked = {}
        total_blocked = {A: 5000.0}
        clock = staticmethod(lambda: 1000.0)

        @property
        def total_block(self):
            raise EOFError("manager down")

    c = ls.PlayerCounter(clock=Mono())
    c.seen(A)
    assert c.counts(Ctrl()) == (1, 1, 0, 0)


def test_full_flag_rearmed_in_seen_below_cap(caplog):
    c = ls.PlayerCounter(max_players=3, clock=Mono())
    with caplog.at_level(logging.DEBUG, logger=ls.logger.name):
        for i in range(5):
            c.seen(f"198.51.100.{i}")
        assert c.full
        del c.last_seen[next(iter(c.last_seen))]  # repasse sous la borne
        c.seen("192.0.2.1")  # nouvelle IP sous la borne : réarmé
        assert not c.full
        c.seen("192.0.2.2")  # sature de nouveau : nouvelle ligne
    recs = [r for r in caplog.records if "satur" in r.getMessage()]
    assert len(recs) == 2 and c.full
    assert "198.51.100" not in caplog.text and "192.0.2" not in caplog.text
