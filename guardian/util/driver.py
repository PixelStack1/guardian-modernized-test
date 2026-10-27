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

Only the network driver service is touched; nothing interacts with the game process.
"""

from __future__ import annotations

import atexit
import logging
import multiprocessing
from typing import Any

logger = logging.getLogger(__name__)


class DriverLifecycle:
    def __init__(self, windivert: Any) -> None:
        self._wd = windivert
        self.was_registered_before: bool | None = None
        self.loaded_by_guardian = False
        self._cleaned = False

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
        if self._cleaned:
            return
        self._cleaned = True
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
            logger.info("WinDivert driver stopped/unregistered on exit")
        except Exception as e:  # pragma: no cover - best effort
            logger.warning("WinDivert unregister failed: %s", e)
