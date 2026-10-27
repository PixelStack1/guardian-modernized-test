"""Onefile parent watchdog.

A PyInstaller *onefile* exe is two processes: the bootloader (parent) unpacks
the bundle and waits while the real Python program runs in a child.  Killing
only the parent PID (Task Manager "end task" on the visible PID, CI's
``Stop-Process -Id``) used to leave the child alive, still holding its WinDivert
handle: the driver then sits in STOP_PENDING and the next Guardian start blocks
in WinDivertOpen.  When the parent disappears, the child now runs the normal
cleanup (pre-cleanup, children, driver unregister) and exits.
"""

from __future__ import annotations

import os
import sys
import threading
from collections.abc import Callable
from typing import Any

SYNCHRONIZE = 0x00100000
WAIT_TIMEOUT = 0x00000102


def is_onefile_child() -> bool:
    """True when running as the child of a PyInstaller onefile bootloader."""
    meipass = getattr(sys, "_MEIPASS", None)
    if not getattr(sys, "frozen", False) or not meipass:
        return False
    exe_dir = os.path.normcase(os.path.abspath(os.path.dirname(sys.executable)))
    return bool(exe_dir != os.path.normcase(os.path.abspath(meipass)))


def windows_parent_probe(kernel32: Any = None) -> Callable[[], bool] | None:
    """Return a callable "is the parent still alive?" bound to a handle opened now
    (immune to PID reuse), or None if unavailable."""
    try:
        if kernel32 is None:
            if sys.platform != "win32":
                return None
            import ctypes

            kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(SYNCHRONIZE, False, os.getppid())
        if not handle:
            return None
    except Exception:
        return None

    def alive() -> bool:
        try:
            return bool(kernel32.WaitForSingleObject(handle, 0) == WAIT_TIMEOUT)
        except Exception:
            return True  # fail-open: never tear down on a probe error

    return alive


def start_parent_watchdog(
    alive: Callable[[], bool],
    on_parent_exit: Callable[[], Any],
    exit_fn: Callable[[int], Any] = os._exit,
    interval: float = 1.0,
) -> threading.Thread:
    """Daemon thread: when ``alive()`` turns False, run ``on_parent_exit`` then exit."""
    stop = threading.Event()

    def run() -> None:
        while not stop.wait(interval):
            if alive():
                continue
            try:
                on_parent_exit()
            finally:
                exit_fn(0)
            return

    t = threading.Thread(target=run, name="parent-watchdog", daemon=True)
    t.start()
    return t
