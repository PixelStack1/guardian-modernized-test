from unittest import mock

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
