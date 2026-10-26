"""Session en direct en fond : [R] garde la protection, réattache, [Q]/sortie arrêtent."""

import queue

import pytest
from guardian.menu import livesession as ls
from guardian.network.anomaly import SessionMonitor
from tests.test_livescreen import FakeRecorder
from tests.test_totalblock import FakeList


class FakeProc:
    created = 0

    def __init__(self):
        FakeProc.created += 1
        self.started = self.terminated = self.joined = False

    def start(self):
        self.started = True

    def is_alive(self):
        return self.started and not self.terminated

    def terminate(self):
        self.terminated = True

    def join(self, timeout=None):
        self.joined = True


class NullScreen:
    def enter(self):
        pass

    def draw(self, _f):
        pass

    def write(self, _t):
        pass

    def leave(self):
        pass


def make_session(closed=None):
    ctrl = ls.LiveSessionController(
        {},
        FakeList(),
        auto_block=False,
        auto_block_available=True,
        clock=lambda: 1000.0,
    )
    closed = closed if closed is not None else []
    return ls.BackgroundSession(
        FakeProc(),
        queue.Queue(),
        ctrl,
        SessionMonitor(),
        ls.PlayerCounter(),
        FakeRecorder(),
        closers=[lambda: closed.append("writer"), lambda: closed.append("manager")],
    )


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.setattr(ls, "REFRESH_SECONDS", 0.0)
    ls.stop_background()
    yield
    ls.stop_background()


def keys(*seq):
    it = iter(seq)
    pending = list(seq)

    def getwch():
        pending.pop(0)
        return next(it)

    return getwch, lambda: bool(pending)


def test_r_keeps_protection_and_states():
    s = ls.attach_or_start(make_session)
    g, h = keys("a", "t", "r")
    assert ls.live_view(s, g, h, NullScreen()) == "r"
    assert s.alive() and not s.proc.terminated
    assert s.ctrl.auto_block and s.ctrl.total_block
    assert s._thread.is_alive()  # le fil de protection tourne sans la vue
    line = ls.background_status_line()
    assert line and "ACTIVÉ" in line and "fond" in line


def test_background_thread_does_protection_without_view():
    s = ls.attach_or_start(make_session)
    calls = []
    s.ctrl.expire = lambda: calls.append(1)
    import time

    for _ in range(100):
        if calls:
            break
        time.sleep(0.02)
    assert calls


def test_reattach_does_not_spawn_new_proc():
    s1 = ls.attach_or_start(make_session)
    n = FakeProc.created
    s2 = ls.attach_or_start(make_session)
    assert s2 is s1 and FakeProc.created == n


def test_q_stops_everything():
    closed = []
    s = ls.attach_or_start(lambda: make_session(closed))
    g, h = keys("q")
    assert ls.live_view(s, g, h, NullScreen()) == "q"
    ls.stop_background()
    assert s.proc.terminated and s.proc.joined and s.stopped
    assert closed == ["writer", "manager"]
    assert ls.background_session() is None and ls.background_status_line() is None


def test_program_exit_stops_background():
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(ls))
    regs = [
        ast.unparse(n)
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and ast.unparse(n.func) == "atexit.register"
    ]
    assert regs == ["atexit.register(stop_background)"]
    s = ls.attach_or_start(make_session)
    ls.stop_background()  # ce qu'exécute atexit
    assert s.proc.terminated and s.stopped
    ls.stop_background()  # idempotent


def test_main_menu_exit_stops_background(monkeypatch):
    import importlib
    import sys

    # menu.py calcule la liste dynamique à l'import : jamais de réseau en test.
    db = importlib.import_module("util.dynamicblacklist")
    monkeypatch.setattr(db, "get_dynamic_blacklist", lambda: set())
    m = importlib.import_module("guardian.menu.menu")

    live = sys.modules["menu.livesession"]  # module importé par menu.py
    s = live.attach_or_start(make_session)

    def loop(_status):
        raise KeyboardInterrupt

    monkeypatch.setattr(m.Menu, "_main_menu_loop", staticmethod(loop))
    with pytest.raises(KeyboardInterrupt):
        m.Menu.main_menu()
    assert s.proc.terminated and live.background_session() is None


def test_dead_proc_is_cleaned():
    s = ls.attach_or_start(make_session)
    s.proc.terminated = True
    assert ls.background_session() is None and s.stopped


@pytest.mark.parametrize("lang", ["fr", "en"])
def test_key_bar_has_return_and_fits(lang):
    import sys

    rt = sys.modules[ls.t.__module__]
    rt.set_language(lang, persist=False)
    try:
        bar = ls.t("live.keys")
        assert "[R]" in bar and "[Q]" in bar and len(bar) < 100
    finally:
        rt.set_language("fr", persist=False)
