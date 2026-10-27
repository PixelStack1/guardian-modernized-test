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
    monkeypatch.setenv(cimode.PROBE_ENV, "1")
    monkeypatch.setenv("CI", "true")
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
    assert src.index("probe_effective(sys.argv)") < src.index("cimode.enable_dry()")


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
    assert drv.orphan_cleanup(WD) == ["unregister"]  # idempotent : déjà fermés
    log.clear()
    drv.track_handle(H(2))
    assert drv.orphan_cleanup(WD) == ["close", "unregister"]
    assert log == ["close2", "unregister"]  # fermer AVANT de désenregistrer

    class Boom:
        @staticmethod
        def unregister():
            raise OSError("in use")

    drv.track_handle(H(3))
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


def test_managers_are_watched_and_die_with_gui(monkeypatch):
    from util import parentwatch

    calls = []
    monkeypatch.setattr(parentwatch, "watch_worker_parent", lambda: calls.append(1))
    monkeypatch.setattr(
        parentwatch,
        "arm_with_pid",
        lambda pid, purpose, **k: calls.append((pid, purpose)),
    )
    parentwatch.arm_in_child(4242)
    assert calls == [(4242, "Manager server"), 1]
    for rel in ("menu/livesession.py", "network/sessions.py"):
        src = (ROOT / "guardian" / rel).read_text("utf-8")
        assert "Manager()" not in src.replace("watched_manager()", "")
    src = (ROOT / "guardian" / "util" / "parentwatch.py").read_text("utf-8")
    assert "manager.start(initializer=arm_in_child, initargs=(os.getpid(),))" in src


def test_auto_arm_at_import_uses_argv_only_in_children(monkeypatch):
    from util import parentwatch

    got = []
    monkeypatch.setattr(
        parentwatch, "watch_spawn_parent", lambda a, **k: got.append(a) or True
    )
    assert parentwatch.auto_arm(["g.exe", "--multiprocessing-fork", "parent_pid=7"])
    src = (ROOT / "guardian" / "util" / "parentwatch.py").read_text("utf-8")
    assert src.rstrip().endswith("auto_arm()")
    assert parentwatch.spawn_parent_pid(["pytest"]) is None  # inerte ici


def test_ci_diag_only_in_probe_mode_and_spawn_logged(monkeypatch, tmp_path):
    from util import parentwatch

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv(cimode.PROBE_ENV, "1")
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv(cimode.DRY_ENV, "0")
    parentwatch.log_spawn("live capture", 12)
    assert not (tmp_path / "Guardian" / "ci-spawn.log").exists()  # inerte
    monkeypatch.setenv(cimode.DRY_ENV, "1")
    parentwatch.log_spawn("live capture", 12)
    parentwatch.arm_with_pid(0, "x")  # pid nul : rien d'armé, aucune exception
    log = (tmp_path / "Guardian" / "ci-spawn.log").read_text("utf-8")
    assert "spawned child pid=12 purpose=live capture" in log
    assert "arm purpose=x gui_pid=0" in log
    monkeypatch.setenv(cimode.DRY_ENV, "0")
    for rel in ("menu/livesession.py", "network/sessions.py"):
        assert "log_spawn(" in (ROOT / "guardian" / rel).read_text("utf-8")


def test_capture_process_target_is_armed(monkeypatch):
    from util import parentwatch

    calls = []
    monkeypatch.setattr(
        parentwatch,
        "arm_with_pid",
        lambda pid, purpose, **k: calls.append((pid, purpose)),
    )
    parentwatch.armed_target(77, "live capture", lambda a, b: calls.append(a + b), 1, 2)
    assert calls == [(77, "live capture"), 3]
    src = (ROOT / "guardian" / "menu" / "livesession.py").read_text("utf-8")
    assert "target=parentwatch.armed_target" in src


def test_cancel_pending_io_shutdown_then_cancelioex_fail_open():
    from util import driver as d

    class H:
        _handle = 99

    calls = []

    class Dll:
        def WinDivertShutdown(self, h, how):  # noqa: N802
            calls.append(("sd", h, how))

    class K32:
        def CancelIoEx(self, h, ov):  # noqa: N802
            calls.append(("cx", h, ov))
            return 1

    assert d.cancel_pending_io(H(), dll=Dll(), kernel32=K32()) == "shutdown"
    assert calls == [("sd", 99, 3)]
    calls.clear()
    assert d.cancel_pending_io(H(), dll=object(), kernel32=K32()) == "cancelioex"
    assert calls == [("cx", 99, None)]

    class Bad:
        def WinDivertShutdown(self, h, how):  # noqa: N802
            raise OSError("x")

        def __getattr__(self, n):
            raise OSError("y")

    assert d.cancel_pending_io(H(), dll=Bad(), kernel32=Bad()) == "cancel:failed"
    assert d.cancel_pending_io(object()) == "cancel:none"


def test_sentinel_cleanup_unregisters_only_if_owned(monkeypatch):
    from types import SimpleNamespace

    from util import driver as d
    from util import parentwatch

    calls = []
    monkeypatch.setattr(
        d, "orphan_cleanup", lambda: calls.append(os.environ.get(d.OWNED_ENV))
    )
    monkeypatch.delenv(d.OWNED_ENV, raising=False)
    parentwatch._sentinel_cleanup(SimpleNamespace(value=0))()
    assert calls == [None]
    parentwatch._sentinel_cleanup(SimpleNamespace(value=1))()
    assert calls == [None, "1"]
    monkeypatch.delenv(d.OWNED_ENV, raising=False)


def test_sentinel_armed_before_driver_load_and_manager_cleans():
    src = (ROOT / "guardian" / "__main__.py").read_text("utf-8")
    assert src.index("start_driver_sentinel()") < src.index("driver.start()")
    pw = (ROOT / "guardian" / "util" / "parentwatch.py").read_text("utf-8")
    assert 'arm_with_pid(gui_pid, "Manager server", on_exit=orphan_cleanup)' in pw


def test_bench_stages_layout_and_ready_threshold():
    b = load_bench()
    assert b.THRESHOLDS["MAIN_READY_MS"] == 70000
    marks = {"process_start": 10.0, "main_ready": 12.5, "window_shown": 12.25, "x": 1}
    assert b.stage_ms(marks, 10.0) == {
        "process_start": 0,
        "window_shown": 2250,
        "main_ready": 2500,
    }
    assert b.layout_lang(0xF020040C) == 0x040C
    assert b.layout_lang(0x04090409) == 0x0409
    assert set("XATV") <= set(b.AZERTY_ALTGR_KEYS) and {"E", "0"} <= set(
        b.AZERTY_ALTGR_KEYS
    )
    assert b.altgr_sequence("0")[2] == (0x30, True)


def test_startup_marks_recorded_and_inert(monkeypatch):
    monkeypatch.setattr(cimode, "MARKS", {})
    cimode.mark("imports_done")
    first = cimode.MARKS["imports_done"]
    cimode.mark("imports_done")
    assert {"imports_done": first} == cimode.MARKS
    src = (ROOT / "guardian" / "gui" / "app.py").read_text("utf-8")
    for m in ("qt_app_created", "menu_imported", "window_shown"):
        assert f'probe.mark("{m}")' in src
    main = (ROOT / "guardian" / "__main__.py").read_text("utf-8")
    assert (
        'cimode.mark("driver_loaded")' in main and 'cimode.mark("imports_done")' in main
    )


@pytest.mark.parametrize(
    "var", ["GUARDIAN_CI_DRY", "GUARDIAN_DRIVER_OWNED", "GUARDIAN_CI_PROBE"]
)
def test_each_env_var_alone_without_ci_keeps_real_filter(monkeypatch, tmp_path, var):
    from util import parentwatch

    for k in (
        *cimode.CI_ENVS,
        cimode.PROBE_ENV,
        cimode.DRY_ENV,
        "GUARDIAN_DRIVER_OWNED",
    ):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv(var, "1")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert not cimode.dry()
    assert sessions.packet_filter(True) == sessions.PACKET_FILTER
    assert sessions.packet_filter(False) == sessions.PACKET_FILTER_6672_ONLY
    assert cimode.probe_effective(["g", "--ci-probe", "p.json"]) is None
    parentwatch.ci_diag("x")
    assert not (tmp_path / "Guardian" / "ci-spawn.log").exists()


def test_probe_refused_in_console_mode():
    ok = {"GUARDIAN_CI_PROBE": "1", "CI": "true"}
    assert cimode.probe_effective(["g", "--ci-probe", "p.json"], ok) == Path("p.json")
    assert (
        cimode.probe_effective(["g", "--console", "--ci-probe", "p.json"], ok) is None
    )
    assert (
        cimode.probe_effective(["g", "--ci-probe", "p.json", "--console"], ok) is None
    )
    assert (
        cimode.probe_effective(["g", "--self-test-exit", "--ci-probe", "p.json"], ok)
        is None
    )


def test_main_pops_inherited_ci_and_owned_env_first():
    src = (ROOT / "guardian" / "__main__.py").read_text("utf-8")
    body = src[src.index('if __name__ == "__main__":') :]
    assert body.index("freeze_support()") < body.index("pop(cimode.DRY_ENV")
    assert body.index("freeze_support()") < body.index("pop(OWNED_ENV")
    assert body.index("pop(cimode.DRY_ENV") < body.index("probe_effective(sys.argv)")
    assert body.index("pop(OWNED_ENV") < body.index("mark_owned(")


def test_orphan_cleanup_idempotent_under_concurrency(monkeypatch):
    import threading

    from util import driver as d

    monkeypatch.delenv(d.OWNED_ENV, raising=False)
    closes = []

    class H:
        def close(self):
            closes.append(1)

    monkeypatch.setattr(d, "_open_handles", {})
    d.track_handle(H())
    barrier = threading.Barrier(4)

    def go():
        barrier.wait()
        d.orphan_cleanup()

    ts = [threading.Thread(target=go) for _ in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(5)
    assert closes == [1]


def test_bench_sniff_is_read_only():
    b = load_bench()
    src = (ROOT / "tests" / "windows" / "acceptance.py").read_text("utf-8")
    assert "Flag.SNIFF | Flag.RECV_ONLY | Flag.NO_INSTALL" in src
    fn = src[src.index("def sniff_check") : src.index("def spawn_log_path")]
    assert ".send(" not in fn and "src_addr" not in fn and "dst_addr" not in fn
    assert b.SNIFF_WINDOW_S == 10.0


_ENV_PROBE_SCRIPT = r"""
import ctypes, json, multiprocessing, os, runpy, sys
from unittest import mock
if sys.platform != "win32" and not hasattr(ctypes, "WinDLL"):
    ctypes.WinDLL = mock.MagicMock()  # comme tests/conftest.py
mode, main_py = sys.argv[1], sys.argv[2]
from util import cimode, driver

def report(stage):
    print(json.dumps({
        "stage": stage,
        "dry_env": os.environ.get(cimode.DRY_ENV),
        "owned": os.environ.get(driver.OWNED_ENV),
        "dry": cimode.dry(),
    }), flush=True)
    sys.exit(0)

if mode == "child":
    # Un enfant est aiguillé dans freeze_support (spawn_main) et n'en revient pas.
    multiprocessing.freeze_support = lambda: report("child")
    sys.argv = [main_py, "--multiprocessing-fork", "parent_pid=%d" % os.getpid(),
                "pipe_handle=1"]
else:
    # Processus principal : on s'arrête juste après les pop, puis la GUI pose
    # elle-même le marqueur via mark_owned (env transmis aux enfants).
    multiprocessing.freeze_support = lambda: None
    def stop(argv, env=None):
        driver.mark_owned(mode == "parent-owned")
        report("parent")
    cimode.probe_effective = stop
    sys.argv = [main_py]
runpy.run_path(main_py, run_name="__main__")
"""


def _run_env_probe(mode, env, tmp_path):
    import subprocess

    script = tmp_path / "envprobe.py"
    script.write_text(_ENV_PROBE_SCRIPT, "utf-8")
    full = {
        k: v
        for k, v in os.environ.items()
        if k
        not in (
            *cimode.CI_ENVS,
            cimode.PROBE_ENV,
            cimode.DRY_ENV,
            "GUARDIAN_DRIVER_OWNED",
        )
    }
    full.update(env)
    paths = [str(ROOT / "guardian")]
    spec = importlib.util.find_spec("pydivert")
    if spec is None or "_fakes" in (spec.origin or ""):
        pytest.skip("pydivert réel absent (stub tests/_fakes)")
    full["PYTHONPATH"] = os.pathsep.join(paths)
    full["HOME"] = full["LOCALAPPDATA"] = full["APPDATA"] = str(tmp_path)
    full["XDG_DATA_HOME"] = str(tmp_path)
    r = subprocess.run(
        [sys.executable, str(script), mode, str(ROOT / "guardian" / "__main__.py")],
        capture_output=True,
        text=True,
        env=full,
        timeout=60,
    )
    line = [x for x in r.stdout.splitlines() if x.startswith("{")]
    assert line, r.stdout + r.stderr
    return json.loads(line[-1])


def test_child_argv_keeps_ci_and_owned_env_parent_drops_inherited(tmp_path):
    ci = {"GUARDIAN_CI_PROBE": "1", "CI": "true"}
    # 1) Mode CI : l'enfant (--multiprocessing-fork) garde le filtre à blanc.
    child = _run_env_probe("child", {**ci, "GUARDIAN_CI_DRY": "1"}, tmp_path)
    assert child["stage"] == "child" and child["dry"] is True
    assert child["dry_env"] == "1"
    # 2) Hors CI : valeurs héritées d'AVANT Guardian effacées par le principal,
    #    donc jamais transmises aux enfants.
    stale = {"GUARDIAN_CI_DRY": "1", "GUARDIAN_DRIVER_OWNED": "1"}
    parent = _run_env_probe("parent", stale, tmp_path)
    assert parent["stage"] == "parent"
    assert parent["dry_env"] is None and parent["owned"] is None and not parent["dry"]
    child_env = {
        k: v
        for k, v in (
            ("GUARDIAN_CI_DRY", parent["dry_env"]),
            ("GUARDIAN_DRIVER_OWNED", parent["owned"]),
        )
        if v
    }
    child = _run_env_probe("child", child_env, tmp_path)
    assert child["owned"] is None and child["dry_env"] is None and not child["dry"]
    # 3) Le principal pose lui-même OWNED=1 (mark_owned, après le pop) : l'enfant le voit.
    parent = _run_env_probe("parent-owned", stale, tmp_path)
    assert parent["owned"] == "1" and parent["dry_env"] is None
    child = _run_env_probe(
        "child", {"GUARDIAN_DRIVER_OWNED": parent["owned"]}, tmp_path
    )
    assert child["owned"] == "1"
