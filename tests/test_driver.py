from unittest import mock

import pytest
from guardian.util import driver as d


def make_wd(registered: bool):
    wd = mock.Mock()
    wd.is_registered.return_value = registered
    return wd


def test_loaded_by_guardian_is_unregistered_once():
    wd = make_wd(False)
    with mock.patch.object(d.atexit, "register") as reg:
        lc = d.DriverLifecycle(wd)
        lc.start()
    wd.register.assert_called_once()
    reg.assert_called_once_with(lc.cleanup)
    child = mock.Mock()
    with mock.patch.object(d.multiprocessing, "active_children", return_value=[child]):
        lc.cleanup()
        lc.cleanup()  # idempotent (finally + atexit)
    child.terminate.assert_called_once()
    wd.unregister.assert_called_once()


def test_children_terminated_before_unregister():
    wd = make_wd(False)
    order = []
    child = mock.Mock()
    child.terminate.side_effect = lambda: order.append("terminate")
    wd.unregister.side_effect = lambda: order.append("unregister")
    with mock.patch.object(d.atexit, "register"):
        lc = d.DriverLifecycle(wd)
        lc.start()
    with mock.patch.object(d.multiprocessing, "active_children", return_value=[child]):
        lc.cleanup()
    assert order == ["terminate", "unregister"]


def test_preexisting_driver_left_alone():
    wd = make_wd(True)
    with mock.patch.object(d.atexit, "register"):
        lc = d.DriverLifecycle(wd)
        lc.start()
        lc.cleanup()
    wd.register.assert_not_called()
    wd.unregister.assert_not_called()


def test_unregister_failure_is_swallowed():
    wd = make_wd(False)
    wd.unregister.side_effect = OSError("busy")
    with mock.patch.object(d.atexit, "register"):
        lc = d.DriverLifecycle(wd)
        lc.start()
        lc.cleanup()  # must not raise


# -- fermeture unique du handle WinDivert (fil de capture vs nettoyage orphelin) --
class _FakeHandle:
    instances: list["_FakeHandle"] = []

    def __init__(self, *a, **k):
        self.closes = 0
        self.is_open = False
        self._handle = None
        _FakeHandle.instances.append(self)

    def open(self):
        self.is_open = True

    def close(self):
        self.closes += 1
        if not self.is_open:
            raise OSError(6, "The handle is invalid")
        self.is_open = False


def _patched_sessions(monkeypatch):
    import threading as th

    from network import sessions
    from util import driver

    _FakeHandle.instances.clear()
    monkeypatch.setattr(sessions.pydivert, "WinDivert", _FakeHandle)
    monkeypatch.setattr(driver, "_open_handles", {})
    monkeypatch.setattr(driver, "_orphan_requested", th.Event())
    monkeypatch.setattr(driver, "_orphan_done", th.Event())
    monkeypatch.delenv(driver.OWNED_ENV, raising=False)
    return sessions, driver


def test_open_windivert_closes_once_on_normal_exit(monkeypatch):
    sessions, _ = _patched_sessions(monkeypatch)
    with sessions.open_windivert(filter_="false"):
        pass
    assert [h.closes for h in _FakeHandle.instances] == [1]


def test_open_windivert_closes_on_exception_without_masking_it(monkeypatch):
    sessions, _ = _patched_sessions(monkeypatch)
    with (
        pytest.raises(ValueError, match="boom"),
        sessions.open_windivert(filter_="false"),
    ):
        raise ValueError("boom")
    assert [h.closes for h in _FakeHandle.instances] == [1]


def test_open_windivert_no_double_close_after_orphan_cleanup(monkeypatch):
    """Run 40594985005 : le nettoyage orphelin (autre fil) ferme le handle, la
    lecture échoue (WinError 232) puis le finally refermait -> WinError 6."""
    sessions, driver = _patched_sessions(monkeypatch)
    with pytest.raises(BrokenPipeError), sessions.open_windivert(filter_="false"):
        assert driver.orphan_cleanup() == ["close"]
        assert driver.orphan_shutdown_requested()
        assert driver.wait_orphan_cleanup(0)
        raise BrokenPipeError(232, "The pipe is being closed")
    assert [h.closes for h in _FakeHandle.instances] == [1]


def test_close_handle_never_raises():
    from util import driver

    class Bad:
        is_open = True

        def close(self):
            raise OSError(6, "The handle is invalid")

    assert driver.close_handle(Bad()) == "close:failed"


def test_multiprocessing_child_streams_never_none():
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "guardian" / "__main__.py").read_text(
        "utf-8"
    )
    assert src.index("ensure_child_streams(sys.argv)") < src.index("freeze_support()\n")


# -- relance : pilote RUNNING exigé (borné), jamais d'attente silencieuse --------
def test_wait_running_ok_and_timeout_are_bounded():
    from util import driver

    states = iter(["STOPPED", "START_PENDING", "RUNNING"])
    t = [0.0]

    def clock():
        return t[0]

    def sleep(s):
        t[0] += s

    assert driver.wait_running(1.0, lambda: next(states), sleep, clock) == (
        True,
        "RUNNING",
    )
    t[0] = 0.0
    ok, last = driver.wait_running(1.0, lambda: "STOPPED", sleep, clock)
    assert (ok, last) == (False, "STOPPED")
    assert t[0] <= 1.2  # borné


def test_call_bounded_times_out_with_clear_error():
    import threading as th

    from util import driver

    gate = th.Event()
    with pytest.raises(driver.DriverStartTimeout, match="driver start: not finished"):
        driver.call_bounded(gate.wait, 0.05, "driver start")
    gate.set()
    assert driver.call_bounded(lambda: 7, 1, "x") == 7
    with pytest.raises(ValueError):
        driver.call_bounded(lambda: (_ for _ in ()).throw(ValueError("v")), 1, "x")


def test_service_state_read_only_and_closes_handles():
    from util import driver

    closed: list[int] = []

    class Adv:
        def __init__(self, svc: int, state: int = 4):
            self.svc, self.state, self.access = svc, state, []

        def OpenSCManagerW(self, a, b, access):
            self.access.append(access)
            return 1

        def OpenServiceW(self, scm, name, access):
            self.access.append(access)
            return self.svc

        def QueryServiceStatus(self, svc, ptr):
            ptr._obj[1] = self.state
            return 1

        def CloseServiceHandle(self, h):
            closed.append(h)
            return 1

    a = Adv(2, 4)
    assert driver.service_state(advapi32=a) == "RUNNING"
    assert a.access == [0x0001, 0x0004]  # CONNECT + QUERY_STATUS seulement
    assert closed == [2, 1]
    assert driver.service_state(advapi32=Adv(2, 1)) == "STOPPED"


def test_main_checks_driver_running_and_bounds_start():
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "guardian" / "__main__.py").read_text(
        "utf-8"
    )
    assert "= lambda: driver.start()" in src
    assert 'call_bounded(start_driver, DRIVER_START_TIMEOUT_S, "driver start")' in src
    assert src.index("probe_filter(extra_ports_enabled())") < src.index(
        "wait_running(DRIVER_RUNNING_TIMEOUT_S)"
    )
    assert "sys.exit(5)" in src
    # banc CI : pas de boîte modale (attente infinie), message journalisé
    notify = src[src.index("def notify") : src.index("def ensure_child_streams")]
    assert notify.index("_ci_probe()") < notify.index("MessageBoxW")


def test_ci_faults_only_in_ci_probe_mode(monkeypatch):
    from util import cimode

    monkeypatch.setenv(cimode.FAULT_ENV, cimode.FAULT_DRIVER_ABSENT)
    for k in ("CI", "GITHUB_ACTIONS", cimode.PROBE_ENV, cimode.DRY_ENV):
        monkeypatch.delenv(k, raising=False)
    assert cimode.fault() is None  # hors banc : jamais honorée
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv(cimode.PROBE_ENV, "1")
    assert cimode.fault() is None  # sonde non active (pas de dry)
    monkeypatch.setenv(cimode.DRY_ENV, "1")
    assert cimode.fault() == cimode.FAULT_DRIVER_ABSENT
    monkeypatch.setenv(cimode.FAULT_ENV, "anything")
    assert cimode.fault() is None


def test_main_ci_faults_wired_to_exit_5_and_6():
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "guardian" / "__main__.py").read_text(
        "utf-8"
    )
    blocked = src.index("cimode.FAULT_DRIVER_BLOCKED")
    assert blocked < src.index("call_bounded(start_driver, DRIVER_START_TIMEOUT_S")
    import re

    assert re.compile(r"os\._exit\(\s*6\s*\)").search(src, blocked)
    absent = src.index("cimode.FAULT_DRIVER_ABSENT")
    assert (
        absent
        < src.index("wait_running(DRIVER_RUNNING_TIMEOUT_S)")
        < src.index("sys.exit(5)")
    )


def test_r1_driver_start_timeout_marks_sentinel_owned_when_service_was_absent():
    """Audit R1 : état lu AVANT driver.start ; s'il était ABSENT, la sentinelle est
    marquée propriétaire (owned=1) AVANT os._exit(6)."""
    import re
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "guardian" / "__main__.py").read_text(
        "utf-8"
    )
    before = src.index("state_before_start = service_state()")
    assert before < src.index("call_bounded(start_driver, DRIVER_START_TIMEOUT_S")
    timeout = src.index("except DriverStartTimeout as e:", before)
    owned = src.index("sentinel_owned.value = 1", timeout)
    assert 'state_before_start == "ABSENT"' in src[timeout:owned]
    exit6 = re.compile(r"os\._exit\(\s*6\s*\)").search(src, timeout)
    assert exit6 and owned < exit6.start()
    # ce bloc précède la première sortie 6 (chargement du pilote)
    assert src.index("except DriverStartTimeout as e:") == timeout
