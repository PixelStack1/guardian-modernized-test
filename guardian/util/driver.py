"""
WinDivert driver lifecycle for Guardian.

Policy (documented choice):
- At start-up we record whether the WinDivert service was already registered.
- Guardian only stops/unregisters the driver on exit if *Guardian itself* registered it
  (it was not present before). If another WinDivert-based tool already had it loaded, we leave it alone.
- Before unregistering, Guardian's own filter child processes are terminated so that no Guardian
  handle is still open. If some other program opened a WinDivert handle in the meantime, the driver
  cannot unload while that handle is open: `sc stop` simply fails and the other program keeps working
  (pydivert re-registers the service on its next open).
- Cleanup is idempotent and runs on normal exit, Ctrl+C (KeyboardInterrupt -> finally) and best-effort
  via atexit on unhandled exceptions. It cannot run if the process is killed hard (TerminateProcess).

Lot 7 (arrêt propre) : avant de fermer le pilote, les fonctions ``add_pre_cleanup``
(arrêt de la session en fond = fermeture de NOTRE handle WinDivert) sont appelées dans
l'ordre inverse d'enregistrement ; puis les processus enfants ; puis le service.
``install_console_handler`` (SetConsoleCtrlHandler) ne couvre que les processus
AVEC console (mode ``--console``) : Ctrl+C, fermeture de la console et, pour une
console, déconnexion/arrêt. Dans l'exe fenêtré Qt (sans console), Windows n'envoie
PAS CTRL_LOGOFF/CTRL_SHUTDOWN à ce gestionnaire : la fin de session y est gérée par
``QGuiApplication.commitDataRequest`` (gui/app.py), qui appelle le même ``cleanup``
idempotent, puis ``aboutToQuit``. Toute erreur est journalisée et n'empêche jamais
les étapes suivantes.

Only the network driver service is touched; nothing interacts with the game process.
"""

from __future__ import annotations

import atexit
import logging
import multiprocessing
import sys
import threading
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

# Événements de SetConsoleCtrlHandler.
CTRL_C_EVENT = 0
CTRL_BREAK_EVENT = 1
CTRL_CLOSE_EVENT = 2
CTRL_LOGOFF_EVENT = 5
CTRL_SHUTDOWN_EVENT = 6
SHUTDOWN_EVENTS = (CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT)


class DriverLifecycle:
    def __init__(self, windivert: Any) -> None:
        self._wd = windivert
        self.was_registered_before: bool | None = None
        self.loaded_by_guardian = False
        self._cleaned = False
        self._lock = threading.Lock()
        self._done = threading.Event()
        self._pre: list[Callable[[], Any]] = []
        self._handler: Any = None
        self.steps: list[str] = []  # journal de l'arrêt (tests, history.log)

    def add_pre_cleanup(self, fn: Callable[[], Any]) -> None:
        """À appeler avant la fermeture du pilote (ex. arrêt de la session en fond)."""
        self._pre.append(fn)

    def start(self) -> None:
        self.was_registered_before = bool(self._wd.is_registered())
        if not self.was_registered_before:
            self._wd.register()
            self.loaded_by_guardian = True
        atexit.register(self.cleanup)
        logger.info(
            "WinDivert registered before start: %s; loaded by Guardian: %s",
            self.was_registered_before,
            self.loaded_by_guardian,
        )

    def cleanup(self) -> None:
        with self._lock:
            already = self._cleaned
            self._cleaned = True
        if already:
            # Un autre appelant nettoie déjà : attendre qu'il ait fini (unregister compris)
            # avant de rendre la main (ex. watchdog suivi de os._exit).
            self._done.wait(10)
            return
        try:
            self._cleanup_steps()
        finally:
            self._done.set()

    def _cleanup_steps(self) -> None:
        for fn in reversed(self._pre):
            try:
                fn()
                self.steps.append("pre")
            except Exception as e:
                logger.warning("Pre-cleanup %r failed: %s", fn, e)
        self.steps.append("children")
        # Close our own handles first: filters run in child processes.
        for child in multiprocessing.active_children():
            try:
                child.terminate()
                child.join(timeout=5)
            except Exception as e:  # pragma: no cover - best effort
                logger.warning("Could not terminate child %s: %s", child, e)
        if not self.loaded_by_guardian:
            logger.info("WinDivert was not loaded by Guardian; leaving it running")
            return
        try:
            self._wd.unregister()
            self.steps.append("unregister")
            logger.info("WinDivert driver stopped/unregistered on exit")
        except Exception as e:  # pragma: no cover - best effort
            logger.warning("WinDivert unregister failed: %s", e)

    def console_event(self, event: int) -> bool:
        """Rappel de SetConsoleCtrlHandler : nettoie sur fermeture/déconnexion/arrêt.
        Renvoie False (Windows applique ensuite son traitement par défaut)."""
        if event in SHUTDOWN_EVENTS or event in (CTRL_C_EVENT, CTRL_BREAK_EVENT):
            try:
                self.cleanup()
            except Exception as e:  # pragma: no cover - best effort
                logger.warning("Console-event cleanup failed: %s", e)
        return False

    def install_console_handler(self, kernel32: Any = None) -> bool:
        """Windows : nettoyage aussi à la fermeture de la console et à l'arrêt."""
        try:
            if kernel32 is None:
                if sys.platform != "win32":
                    return False
                import ctypes

                kernel32 = ctypes.windll.kernel32
                proto = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_uint)
                self._handler = proto(lambda ev: int(self.console_event(int(ev))))
            else:
                self._handler = self.console_event
            return bool(kernel32.SetConsoleCtrlHandler(self._handler, True))
        except Exception as e:
            logger.warning("SetConsoleCtrlHandler failed: %s", e)
            return False


# Lot 8 — GUI tuée (taskkill /F) : les workers survivants nettoient eux-mêmes.
OWNED_ENV = "GUARDIAN_DRIVER_OWNED"  # « 1 » si Guardian a chargé le pilote (hérité)
_open_handles: dict[int, Any] = {}  # par id() : aucun appel à __hash__
_handles_lock = threading.Lock()


def track_handle(handle: Any) -> None:
    with _handles_lock:
        _open_handles[id(handle)] = handle


def untrack_handle(handle: Any) -> None:
    with _handles_lock:
        _open_handles.pop(id(handle), None)


def mark_owned(loaded_by_guardian: bool) -> None:
    """Transmis aux workers lancés ensuite (environnement hérité)."""
    import os

    if loaded_by_guardian:
        os.environ[OWNED_ENV] = "1"


WINDIVERT_SHUTDOWN_BOTH = 3


def cancel_pending_io(handle: Any, dll: Any = None, kernel32: Any = None) -> str:
    """Débloque une lecture WinDivertRecv en attente avant la fermeture :
    WinDivertShutdown(h, BOTH) si la DLL l'exporte (WinDivert >= 2.0), sinon
    CancelIoEx(h, NULL). Fail-open, journalisé, jamais d'exception."""
    raw = getattr(handle, "_handle", None)
    if not raw:
        return "cancel:none"
    try:
        if dll is None:
            from pydivert import windivert_dll as _dll

            dll = _dll
        fn = getattr(dll, "WinDivertShutdown", None)
        if fn is not None:
            fn(raw, WINDIVERT_SHUTDOWN_BOTH)
            logger.warning("orphan cleanup: WinDivertShutdown(BOTH) ok")
            return "shutdown"
    except Exception as e:
        logger.warning("orphan cleanup: WinDivertShutdown failed: %s", e)
    try:
        if kernel32 is None:
            import ctypes
            from ctypes import wintypes as wt

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CancelIoEx.argtypes = [wt.HANDLE, ctypes.c_void_p]
            kernel32.CancelIoEx.restype = wt.BOOL
        ok = kernel32.CancelIoEx(raw, None)
        logger.warning("orphan cleanup: CancelIoEx -> %s", ok)
        return "cancelioex"
    except Exception as e:
        logger.warning("orphan cleanup: CancelIoEx failed: %s", e)
        return "cancel:failed"


def orphan_cleanup(windivert: Any = None) -> list[str]:
    """Appelé dans un worker quand la GUI a disparu : fermer NOS handles (fail-open :
    le trafic n'est plus détourné), puis, si Guardian avait chargé le pilote, le
    désenregistrer (échoue sans effet tant qu'un autre handle reste ouvert ; le
    dernier worker à fermer réussit). Jamais d'exception."""
    import os

    steps: list[str] = []
    with _handles_lock:  # idempotent : un seul appel concurrent ferme chaque handle
        handles = list(_open_handles.values())
        _open_handles.clear()
    for h in handles:
        r = cancel_pending_io(h)
        if r != "cancel:none":
            steps.append(r)
    for h in handles:
        try:
            h.close()
            steps.append("close")
        except Exception as e:
            logger.warning("orphan cleanup: close failed: %s", e)
    if os.environ.get(OWNED_ENV) != "1":
        return steps
    try:
        if windivert is None:
            import pydivert

            windivert = pydivert.WinDivert
        windivert.unregister()
        steps.append("unregister")
    except Exception as e:
        logger.warning("orphan cleanup: unregister failed: %s", e)
    return steps
