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
