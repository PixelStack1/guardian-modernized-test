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
            if self._cleaned:
                return
            self._cleaned = True
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
