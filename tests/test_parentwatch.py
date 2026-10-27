import sys
import threading
from pathlib import Path

from util import parentwatch


def test_watchdog_cleans_up_then_exits_when_parent_dies():
    state = {"alive": True}
    calls: list[str] = []
    done = threading.Event()

    def exit_fn(code):
        calls.append(f"exit{code}")
        done.set()

    parentwatch.start_parent_watchdog(
        lambda: state["alive"], lambda: calls.append("cleanup"), exit_fn, interval=0.01
    )
    assert not done.wait(0.1)
    state["alive"] = False
    assert done.wait(2)
    assert calls == ["cleanup", "exit0"]


def test_watchdog_logs_cleanup_error_and_still_exits(caplog):
    import logging

    done = threading.Event()

    def boom():
        raise RuntimeError("x")

    with caplog.at_level(logging.ERROR, logger="debugger"):
        t = parentwatch.start_parent_watchdog(
            lambda: False, boom, lambda c: done.set(), 0.01
        )
        assert done.wait(2)
        t.join(2)
    assert any(
        r.name == "debugger" and r.exc_info and "x" in str(r.exc_info[1])
        for r in caplog.records
    )


def test_probe_uses_handle_and_fails_open():
    class K:
        def __init__(self, result):
            self.result = result

        def OpenProcess(self, access, inherit, pid):
            assert access == parentwatch.SYNCHRONIZE
            return 42

        def WaitForSingleObject(self, h, ms):
            if self.result is None:
                raise OSError
            return self.result

    assert parentwatch.windows_parent_probe(K(parentwatch.WAIT_TIMEOUT))() is True
    assert parentwatch.windows_parent_probe(K(0))() is False
    assert parentwatch.windows_parent_probe(K(None))() is True


def test_onefile_detection(monkeypatch, tmp_path):
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert not parentwatch.is_onefile_child()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path / "_MEI1"), raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "app" / "Guardian.exe"))
    assert parentwatch.is_onefile_child()
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path / "app"), raising=False)
    assert not parentwatch.is_onefile_child()


def test_main_arms_watchdog_after_driver_start_before_self_test():
    src = (Path(__file__).resolve().parents[1] / "guardian" / "__main__.py").read_text(
        "utf-8"
    )
    i_start = src.index("driver.start()")
    i_watch = src.index("start_parent_watchdog(probe, driver.cleanup)")
    i_self = src.index('"--self-test-exit" in sys.argv:')
    assert i_start < i_watch < i_self


def test_onefile_detection_rejects_onedir_internal(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "app" / "Guardian.exe"))
    monkeypatch.setattr(
        sys, "_MEIPASS", str(tmp_path / "app" / "_internal"), raising=False
    )
    assert not parentwatch.is_onefile_child()
    monkeypatch.setattr(
        sys, "_MEIPASS", str(tmp_path / "x" / "_MEI12345"), raising=False
    )
    assert parentwatch.is_onefile_child()


def test_concurrent_cleanup_second_caller_waits_for_unregister():
    from util.driver import DriverLifecycle

    entered = threading.Event()
    release = threading.Event()
    events: list[str] = []

    class WD:
        def is_registered(self):
            return False

        def register(self):
            pass

        def unregister(self):
            events.append("unregister")

    d = DriverLifecycle(WD())

    def slow_pre():
        entered.set()
        release.wait(5)

    d.loaded_by_guardian = True
    d.add_pre_cleanup(slow_pre)
    first = threading.Thread(target=d.cleanup)
    first.start()
    assert entered.wait(2)
    second_done = threading.Event()

    def second():
        d.cleanup()
        events.append("second-returned")
        second_done.set()

    threading.Thread(target=second).start()
    assert not second_done.wait(0.2)  # must wait for the first caller
    release.set()
    assert second_done.wait(5)
    first.join(5)
    assert events == ["unregister", "second-returned"]
