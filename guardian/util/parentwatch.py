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

import logging
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
    if not os.path.basename(os.path.normpath(meipass)).startswith("_MEI"):
        return False  # onedir (_internal) : pas de bootloader parent
    exe_dir = os.path.normcase(os.path.abspath(os.path.dirname(sys.executable)))
    return bool(exe_dir != os.path.normcase(os.path.abspath(meipass)))


def windows_parent_probe(
    kernel32: Any = None, pid: int | None = None
) -> Callable[[], bool] | None:
    """Return a callable "is the parent still alive?" bound to a handle opened now
    (immune to PID reuse), or None if unavailable."""
    try:
        if kernel32 is None:
            if sys.platform != "win32":
                return None
            import ctypes

            kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(
            SYNCHRONIZE, False, os.getppid() if pid is None else pid
        )
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
            except Exception:
                logging.getLogger("debugger").exception(
                    "parent watchdog: cleanup after parent exit failed"
                )
            finally:
                exit_fn(0)
            return

    t = threading.Thread(target=run, name="parent-watchdog", daemon=True)
    t.start()
    return t


_worker_watch_started = False


def watch_worker_parent(
    probe: Callable[[int], Callable[[], bool] | None] | None = None,
    start: Callable[..., Any] = start_parent_watchdog,
) -> bool:
    """Capture workers (multiprocessing children holding a WinDivert handle):
    exit when the GUI process that spawned them disappears (taskkill /F, crash),
    so the handle closes and the driver can unload — fail-open, never an orphan
    diverting traffic. No-op in the main process; idempotent."""
    global _worker_watch_started
    import multiprocessing

    parent = multiprocessing.parent_process()
    ppid = getattr(parent, "pid", None)
    if _worker_watch_started or not ppid:
        return False
    # PID du processus qui a lancé le worker (la GUI), pas os.getppid() : en onefile
    # le worker passe par son propre bootloader, qui serait alors le « parent ».
    alive = windows_parent_probe(pid=ppid) if probe is None else probe(ppid)
    if alive is None:
        return False
    start(alive, lambda: None)
    _worker_watch_started = True
    return True


def spawn_parent_pid(argv: list[str]) -> int | None:
    """PID du lanceur d'un enfant multiprocessing (``--multiprocessing-fork
    parent_pid=N …``), sinon None."""
    if "--multiprocessing-fork" not in argv:
        return None
    for arg in argv:
        if arg.startswith("parent_pid="):
            try:
                pid = int(arg.split("=", 1)[1])
            except ValueError:
                return None
            return pid if pid > 0 else None
    return None


def watch_spawn_parent(
    argv: list[str],
    probe: Callable[[int], Callable[[], bool] | None] | None = None,
    start: Callable[..., Any] = start_parent_watchdog,
) -> bool:
    """Tout enfant multiprocessing (worker de capture, serveur Manager) se termine
    quand son lanceur (la GUI) disparaît — handle WinDivert fermé, aucun orphelin.
    À appeler avant freeze_support(). No-op hors enfant multiprocessing."""
    global _worker_watch_started
    pid = spawn_parent_pid(argv)
    if pid is None or _worker_watch_started:
        return False
    alive = windows_parent_probe(pid=pid) if probe is None else probe(pid)
    if alive is None:
        return False
    start(alive, lambda: None)
    _worker_watch_started = True
    return True
