"""Lot 8 : mode sonde CI (--ci-probe) et fonctions pures du banc Windows."""

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from tests.gui_fakes import FakeConfig, feed, make_session  # noqa: E402
from tests.test_lot7_extras import FakeApi  # noqa: E402

from network import sessions  # noqa: E402
from util import cimode, exehash, health  # noqa: E402
from util.hotkeys import DEFAULT_HOTKEYS  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def load_bench():
    spec = importlib.util.spec_from_file_location(
        "acceptance", ROOT / "tests" / "windows" / "acceptance.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["acceptance"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_probe_flag_parsing_is_inert_without_flag():
    assert cimode.probe_path(["Guardian.exe"]) is None
    assert cimode.probe_path(["g", "--console"]) is None
    assert cimode.probe_path(["g", "--ci-probe"]) is None
    assert cimode.probe_path(["g", "--ci-probe", "--console"]) is None
    assert cimode.probe_path(["g", "--ci-probe", "C:/p.json"]) == Path("C:/p.json")


def test_dry_filter_only_when_enabled(monkeypatch):
    monkeypatch.setenv(cimode.DRY_ENV, "0")  # restauré (absent) en fin de test
    assert not cimode.dry()
    assert sessions.packet_filter(True) == sessions.PACKET_FILTER
    cimode.enable_dry()
    try:
        assert cimode.dry()
        assert sessions.packet_filter(True) == "false"
        assert sessions.packet_filter(False) == "false"
    finally:
        os.environ[cimode.DRY_ENV] = "0"
    assert sessions.packet_filter(False) == sessions.PACKET_FILTER_6672_ONLY


def test_main_enables_probe_before_driver_and_passes_it_to_gui():
    src = (ROOT / "guardian" / "__main__.py").read_text("utf-8")
    assert src.index("cimode.enable_dry()") < src.index("driver.start()")
    assert (
        "run_gui(version=__version__, on_shutdown=driver.cleanup, probe=gui_probe)"
        in src
    )
    app = (ROOT / "guardian" / "gui" / "app.py").read_text("utf-8")
    assert 'probe.mark("startup_window")' in app and "probe.attach(win)" in app


@pytest.fixture
def win(qtbot, tmp_path):
    from gui.window import MainWindow

    s = make_session(tmp_path, FakeConfig({"language": "fr"}))
    feed(s)
    api = FakeApi()
    w = MainWindow(
        s,
        "3.7",
        hotkey_api=lambda: api,
        checks=health.run_checks(lambda: False, lambda: {}, tmp_path / "x.json"),
        exe=exehash.ExeHash("C:/Guardian.exe", "cd" * 32, True),
    )
    w.timer.stop()
    qtbot.addWidget(w)
    yield w, api
    w.stop_hotkeys()


def test_probe_reports_ui_state_hotkeys_and_hash(win, qtbot, tmp_path):
    from gui.ciprobe import CiProbe

    w, api = win
    path = tmp_path / "probe.json"
    p = CiProbe(path, {"python_start": 1.0})
    p.mark("startup_window")
    assert json.loads(path.read_text("utf-8"))["marks"]["startup_window"] > 0
    p.attach(w, interval_ms=10_000)
    api.press(1)  # emergency
    qtbot.waitUntil(lambda: p.fired == ["emergency"], timeout=2000)
    p.write()
    data = json.loads(path.read_text("utf-8"))
    assert data["pid"] == os.getpid()
    assert set(data["marks"]) >= {"python_start", "startup_window", "main_ready"}
    assert data["fired"] == ["emergency"]
    assert data["state"]["paused"] is True
    assert data["exe_sha256_shown"] == "cd" * 32
    assert sorted(data["hotkeys"]["registered"]) == sorted(
        h.action for h in DEFAULT_HOTKEYS
    )
    assert data["hotkey_ids"]["emergency"] == 1
    assert data["hotkey_keys"]["emergency"] == [
        DEFAULT_HOTKEYS[0].mods,
        DEFAULT_HOTKEYS[0].vk,
    ]
    assert data["hwnd"] > 0
    w.mark_protection_stopped()
    p.write()
    data = json.loads(path.read_text("utf-8"))
    assert data["protection_stopped"] is True
    assert data["status"].startswith(load_bench().STOPPED_TEXT)
    assert "203.0.113" not in path.read_text("utf-8")  # aucune IP dans la sonde


def test_probe_write_never_raises(tmp_path):
    from gui.ciprobe import write_json

    write_json(tmp_path / "missing" / "p.json", {"a": 1})  # dossier absent : ignoré


def test_bench_pure_helpers():
    b = load_bench()
    assert b.driver_active("STATE : 4 RUNNING")
    assert b.driver_active("STATE : 3 STOP_PENDING")
    assert not b.driver_active("[SC] EnumQueryServicesStatus:OpenService FAILED 1060:")
    assert not b.driver_active("STATE : 1 STOPPED")
    assert b.hotkey_lparam(0x0003, 0x7B) == (0x7B << 16) | 3
    seq = b.altgr_sequence("x")
    assert seq[0] == (b.VK_LCONTROL, True) and seq[1] == (b.VK_RMENU, True)
    assert (ord("X"), True) in seq and len(seq) == 6
    assert [d for _vk, d in seq].count(True) == 3
    f12 = b.ctrl_alt_f12_sequence()
    assert (b.VK_F12, True) in f12
    assert b.threshold("SPLASH_MS", {}) == b.THRESHOLDS["SPLASH_MS"]
    assert b.threshold("SPLASH_MS", {"GUARDIAN_ACC_SPLASH_MS": "1234"}) == 1234
    assert b.threshold("SPLASH_MS", {"GUARDIAN_ACC_SPLASH_MS": "x"}) == 5000
    r = b.Report()
    r.check("a", True)
    r.check("b", None)
    r.check("c", False)
    assert r.failed == ["c"]


def test_bench_altgr_letters_are_not_registered_as_ctrl_alt_only():
    """AltGr = Ctrl+Alt : aucune lettre ne doit être enregistrée sans Maj."""
    from util.hotkeys import MOD_ALT, MOD_CONTROL, MOD_SHIFT

    for h in DEFAULT_HOTKEYS:
        if ord("A") <= h.vk <= ord("Z"):
            assert h.mods & MOD_SHIFT and h.mods & MOD_CONTROL and h.mods & MOD_ALT


def test_probe_allowed_only_with_ci_env():
    ok = {"GUARDIAN_CI_PROBE": "1", "CI": "true"}
    assert cimode.probe_allowed(ok)
    assert cimode.probe_allowed({"GUARDIAN_CI_PROBE": "1", "GITHUB_ACTIONS": "true"})
    assert not cimode.probe_allowed({})
    assert not cimode.probe_allowed({"CI": "true"})
    assert not cimode.probe_allowed({"GUARDIAN_CI_PROBE": "1"})
    assert not cimode.probe_allowed({"GUARDIAN_CI_PROBE": "0", "CI": "true"})
    assert not cimode.probe_allowed({"GUARDIAN_CI_PROBE": "1", "CI": "false"})
    src = (ROOT / "guardian" / "__main__.py").read_text("utf-8")
    assert src.index("probe_allowed()") < src.index("cimode.enable_dry()")


def test_probe_json_keys_whitelist_and_no_ip(win, tmp_path):
    from gui.ciprobe import ALLOWED_KEYS, HOTKEY_KEYS, STATE_KEYS, CiProbe, sanitize

    w, _api = win
    path = tmp_path / "probe.json"
    p = CiProbe(path, {"python_start": 1.0})
    p.attach(w, interval_ms=10_000)
    w.status.setText("Bloqué 203.0.113.7 et 2001:db8::1:2 à 12:30:45")
    p.write()
    data = json.loads(path.read_text("utf-8"))
    assert set(data) <= ALLOWED_KEYS
    assert set(data["hotkeys"]) <= HOTKEY_KEYS
    assert set(data["state"]) <= STATE_KEYS
    raw = path.read_text("utf-8")
    assert "203.0.113" not in raw and "2001:db8" not in raw
    assert "12:30:45" in data["status"]
    assert sanitize({"sessions": [1], "ips": ["1.2.3.4"], "pid": 1}) == {"pid": 1}


def test_ci_banner_shown_in_probe_mode_and_i18n(win, tmp_path):
    from gui.ciprobe import CiProbe
    from util.i18n import STRINGS

    w, _api = win
    assert w.ci_banner is None  # usage normal : aucun bandeau
    CiProbe(tmp_path / "p.json", {}).attach(w, interval_ms=10_000)
    assert w.ci_banner is not None
    assert w.ci_banner.text() == "MODE TEST CI — protection désactivée"
    assert STRINGS["gui.ci_banner"]["en"] == "CI TEST MODE — protection disabled"


def test_worker_parent_watchdog_only_in_mp_children(monkeypatch):
    import multiprocessing

    from util import parentwatch

    class Parent:
        pid = 4242

    started, seen = [], []

    def start(*a, **k):
        started.append(a)

    def probe(pid):
        seen.append(pid)
        return lambda: True

    monkeypatch.setattr(parentwatch, "_worker_watch_started", False)
    monkeypatch.setattr(multiprocessing, "parent_process", lambda: None)
    assert not parentwatch.watch_worker_parent(probe, start)  # processus principal
    monkeypatch.setattr(multiprocessing, "parent_process", lambda: Parent())
    assert not parentwatch.watch_worker_parent(lambda pid: None, start)
    assert parentwatch.watch_worker_parent(probe, start)
    assert seen == [4242]  # PID du lanceur (GUI), pas os.getppid()
    assert not parentwatch.watch_worker_parent(probe, start)  # idempotent
    assert len(started) == 1


def test_open_windivert_arms_worker_watchdog():
    src = (ROOT / "guardian" / "network" / "sessions.py").read_text("utf-8")
    body = src[src.index("def open_windivert") : src.index("def probe_filter")]
    assert body.index("handle.open()") < body.index("watch_worker_parent(")


def test_spawn_parent_watchdog_from_argv(monkeypatch):
    from util import parentwatch

    f = parentwatch.spawn_parent_pid
    assert f(["g.exe"]) is None
    assert f(["g.exe", "parent_pid=12"]) is None  # pas un enfant multiprocessing
    argv = ["g.exe", "--multiprocessing-fork", "parent_pid=2596", "pipe_handle=8"]
    assert f(argv) == 2596
    assert f(["g.exe", "--multiprocessing-fork", "parent_pid=x"]) is None
    monkeypatch.setattr(parentwatch, "_worker_watch_started", False)
    started, seen = [], []
    assert not parentwatch.watch_spawn_parent(["g.exe"], lambda p: None)
    assert parentwatch.watch_spawn_parent(
        argv,
        lambda p: seen.append(p) or (lambda: True),
        lambda *a, **k: started.append(a),
    )
    assert seen == [2596] and len(started) == 1
    src = (ROOT / "guardian" / "__main__.py").read_text("utf-8")
    assert src.index("watch_spawn_parent(sys.argv") < src.index("freeze_support()\n")


def test_orphan_cleanup_closes_handles_then_unregisters_if_owned(monkeypatch):
    from util import driver as drv

    log = []

    class H:
        def __init__(self, n):
            self.n = n

        def close(self):
            log.append(f"close{self.n}")

    class Bad:
        def close(self):
            raise OSError("x")

    class WD:
        @staticmethod
        def unregister():
            log.append("unregister")

    monkeypatch.setattr(drv, "_open_handles", {})
    h = H(1)
    drv.track_handle(h)
    drv.track_handle(Bad())
    drv.track_handle(H(2))
    drv.untrack_handle(h)
    monkeypatch.delenv(drv.OWNED_ENV, raising=False)
    assert drv.orphan_cleanup(WD) == ["close"]  # pilote pas chargé par Guardian
    assert log == ["close2"]
    log.clear()
    monkeypatch.setenv(drv.OWNED_ENV, "0")
    drv.mark_owned(False)
    assert os.environ[drv.OWNED_ENV] == "0"
    drv.mark_owned(True)
    assert drv.orphan_cleanup(WD) == ["close", "unregister"]
    assert log == ["close2", "unregister"]  # fermer AVANT de désenregistrer

    class Boom:
        @staticmethod
        def unregister():
            raise OSError("in use")

    assert drv.orphan_cleanup(Boom) == ["close"]  # jamais d'exception


def test_spawn_watchdog_wired_with_orphan_cleanup():
    src = (ROOT / "guardian" / "__main__.py").read_text("utf-8")
    assert "watch_spawn_parent(sys.argv, on_parent_exit=_orphan)" in src
    assert src.index("driver.start()") < src.index(
        "mark_owned(driver.loaded_by_guardian)"
    )
    s = (ROOT / "guardian" / "network" / "sessions.py").read_text("utf-8")
    body = s[s.index("def open_windivert") : s.index("def probe_filter")]
    assert "track_handle(handle)" in body and "untrack_handle(handle)" in body


def test_parent_watchdog_exits_even_if_cleanup_hangs():
    import threading

    from util import parentwatch

    exited = threading.Event()
    block = threading.Event()
    parentwatch.start_parent_watchdog(
        lambda: False,
        lambda: block.wait(30),  # nettoyage bloqué
        lambda code: exited.set(),
        interval=0.01,
        cleanup_timeout=0.2,
    )
    assert exited.wait(3)
    block.set()
