import sys
import threading
from pathlib import Path

import pytest

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


def _ci_env(monkeypatch, tmp_path, dry: bool) -> None:
    from util import cimode

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv(cimode.PROBE_ENV, "1")
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv(cimode.DRY_ENV, "1" if dry else "0")


def test_ci_traceback_inert_outside_ci_probe(monkeypatch, tmp_path):
    _ci_env(monkeypatch, tmp_path, dry=False)
    try:
        raise ValueError("boom")
    except ValueError:
        parentwatch.ci_traceback("test")
    assert not (tmp_path / "Guardian" / parentwatch.CRASH_LOG).exists()


def test_ci_traceback_writes_full_traceback_in_ci_probe(monkeypatch, tmp_path):
    _ci_env(monkeypatch, tmp_path, dry=True)
    try:
        raise ValueError("boom")
    except ValueError:
        parentwatch.ci_traceback("test")
    text = (tmp_path / "Guardian" / parentwatch.CRASH_LOG).read_text("utf-8")
    assert "where=test" in text and "Traceback" in text and "ValueError: boom" in text


def _fresh_orphan_state(monkeypatch, requested: bool = False):
    import threading as th

    from util import driver

    req, done = th.Event(), th.Event()
    at = [0.0]
    if requested:
        import time

        req.set()
        done.set()
        at[0] = time.monotonic()
    monkeypatch.setattr(driver, "_orphan_requested", req)
    monkeypatch.setattr(driver, "_orphan_done", done)
    monkeypatch.setattr(driver, "_orphan_requested_at", at)
    return at


def test_armed_target_unexpected_error_logs_and_exits_1(monkeypatch, tmp_path):
    """Jamais d'exception hors de la cible : multiprocessing écrirait sur
    sys.stderr (None en exe fenêtré) -> boîte modale du chargeur."""
    _ci_env(monkeypatch, tmp_path, dry=True)
    _fresh_orphan_state(monkeypatch)
    monkeypatch.setattr(parentwatch, "arm_with_pid", lambda *a, **k: None)

    def target() -> None:
        raise OSError("recv failed")

    with pytest.raises(SystemExit) as exc:
        parentwatch.armed_target(0, "live capture", target)
    assert exc.value.code == 1
    text = (tmp_path / "Guardian" / parentwatch.CRASH_LOG).read_text("utf-8")
    assert "target live capture" in text and "OSError: recv failed" in text


def test_armed_target_read_error_after_orphan_shutdown_is_clean(monkeypatch, tmp_path):
    _ci_env(monkeypatch, tmp_path, dry=False)
    _fresh_orphan_state(monkeypatch, requested=True)
    monkeypatch.setattr(parentwatch, "arm_with_pid", lambda *a, **k: None)

    def target() -> None:
        raise BrokenPipeError(232, "The pipe is being closed")

    assert parentwatch.armed_target(0, "live capture", target) is None


def test_armed_target_keeps_integer_system_exit(monkeypatch):
    _fresh_orphan_state(monkeypatch)
    monkeypatch.setattr(parentwatch, "arm_with_pid", lambda *a, **k: None)

    def target() -> None:
        raise SystemExit(3)

    with pytest.raises(SystemExit) as exc:
        parentwatch.armed_target(0, "x", target)
    assert exc.value.code == 3


# -- QA : WinError 232 = fin propre SEULEMENT après une demande orpheline récente --
def _raise_232() -> None:
    raise BrokenPipeError(232, "The pipe is being closed")


def test_armed_target_232_without_orphan_request_is_logged_error(monkeypatch, tmp_path):
    _ci_env(monkeypatch, tmp_path, dry=True)
    _fresh_orphan_state(monkeypatch, requested=False)
    monkeypatch.setattr(parentwatch, "arm_with_pid", lambda *a, **k: None)
    with pytest.raises(SystemExit) as exc:
        parentwatch.armed_target(0, "live capture", _raise_232)
    assert exc.value.code == 1
    text = (tmp_path / "Guardian" / parentwatch.CRASH_LOG).read_text("utf-8")
    assert "BrokenPipeError" in text


def test_armed_target_232_with_stale_orphan_request_is_logged_error(monkeypatch):
    at = _fresh_orphan_state(monkeypatch, requested=True)
    at[0] -= 60.0  # demande trop ancienne : pas « juste avant »
    monkeypatch.setattr(parentwatch, "arm_with_pid", lambda *a, **k: None)
    with pytest.raises(SystemExit) as exc:
        parentwatch.armed_target(0, "live capture", _raise_232)
    assert exc.value.code == 1


def test_armed_target_other_error_after_orphan_request_is_logged_error(monkeypatch):
    _fresh_orphan_state(monkeypatch, requested=True)
    monkeypatch.setattr(parentwatch, "arm_with_pid", lambda *a, **k: None)

    def target() -> None:
        raise OSError(6, "The handle is invalid")

    with pytest.raises(SystemExit) as exc:
        parentwatch.armed_target(0, "live capture", target)
    assert exc.value.code == 1


def test_is_shutdown_read_error_only_232():
    e = OSError(22, "x")
    e.winerror = 232  # type: ignore[attr-defined]
    assert parentwatch.is_shutdown_read_error(e)
    assert parentwatch.is_shutdown_read_error(BrokenPipeError(232, "x"))
    assert not parentwatch.is_shutdown_read_error(OSError(6, "x"))
    assert not parentwatch.is_shutdown_read_error(ValueError("232"))


# -- QA : os._exit(1) seulement pour l'amorçage raté d'un enfant --multiprocessing-fork
class _Exit(Exception):
    pass


def _hard_exit(codes):
    def run(code: int) -> None:
        codes.append(code)
        raise _Exit

    return run


def _boot_fail() -> None:
    raise PermissionError(13, "Access is denied")  # WinError 5 (DuplicateHandle)


FORK = ["Guardian.exe", "--multiprocessing-fork", "parent_pid=7224", "pipe_handle=1684"]


def test_fork_child_bootstrap_failure_exits_1_quietly(monkeypatch, tmp_path):
    _ci_env(monkeypatch, tmp_path, dry=True)
    codes: list[int] = []
    with pytest.raises(_Exit):  # os._exit simulé : aucune relance de l'erreur
        parentwatch.run_freeze_support(_boot_fail, FORK, _hard_exit(codes))
    assert codes == [1]
    text = (tmp_path / "Guardian" / parentwatch.CRASH_LOG).read_text("utf-8")
    assert "freeze_support" in text and "PermissionError" in text


def test_fork_child_failure_outside_ci_writes_no_crash_log(monkeypatch, tmp_path):
    _ci_env(monkeypatch, tmp_path, dry=False)
    codes: list[int] = []
    with pytest.raises(_Exit):
        parentwatch.run_freeze_support(_boot_fail, FORK, _hard_exit(codes))
    assert codes == [1]
    assert not (tmp_path / "Guardian" / parentwatch.CRASH_LOG).exists()


def test_fork_child_nonzero_or_text_system_exit_exits_1():
    codes: list[int] = []
    for code in (3, "fatal"):

        def leave(code=code) -> None:
            raise SystemExit(code)

        with pytest.raises(_Exit):
            parentwatch.run_freeze_support(leave, FORK, _hard_exit(codes))
    assert codes == [1, 1]


def test_fork_child_normal_system_exit_passes_through():
    codes: list[int] = []
    for code in (0, None):

        def leave(code=code) -> None:
            raise SystemExit(code)

        with pytest.raises(SystemExit) as exc:
            parentwatch.run_freeze_support(leave, FORK, _hard_exit(codes))
        assert exc.value.code == code
    assert codes == []


def test_non_fork_argv_reraises_never_hard_exits(monkeypatch, tmp_path):
    _ci_env(monkeypatch, tmp_path, dry=False)
    codes: list[int] = []
    with pytest.raises(PermissionError):
        parentwatch.run_freeze_support(_boot_fail, ["Guardian.exe"], _hard_exit(codes))
    for code in (3, "x"):

        def leave(code=code) -> None:
            raise SystemExit(code)

        with pytest.raises(SystemExit):
            parentwatch.run_freeze_support(leave, ["Guardian.exe"], _hard_exit(codes))
    assert codes == []
