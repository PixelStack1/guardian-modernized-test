"""Lancement de la GUI : session en fond (capture dans son processus), fenêtre Qt."""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


def session_end_cleanup(on_shutdown: Callable[[], Any] | None = None) -> None:
    """Fin de session Windows (commitDataRequest) : même nettoyage idempotent que la
    sortie normale (session en fond puis pilote). Jamais d'exception."""
    from menu import livesession as ls

    for fn in (ls.stop_background, on_shutdown):
        if fn is not None:
            try:
                fn()
            except Exception:
                logger.exception("nettoyage de fin de session impossible")


def run_gui(
    factory: Callable[[], Any] | None = None,
    version: str = "",
    on_shutdown: Callable[[], Any] | None = None,
) -> int:  # pragma: no cover - interactif, Windows
    from PySide6.QtGui import QGuiApplication
    from PySide6.QtWidgets import QApplication

    from gui.window import MainWindow
    from menu import livesession as ls

    app = QApplication.instance() or QApplication(sys.argv)
    # Lot 7 : arrêt propre aussi à la fin de session Windows (aboutToQuit).
    app.aboutToQuit.connect(ls.stop_background)
    if isinstance(app, QGuiApplication):
        app.commitDataRequest.connect(lambda _m: session_end_cleanup(on_shutdown))
    session = ls.attach_or_start(factory or ls._create_session)
    win = None
    try:
        win = MainWindow(session, version, global_hotkeys=True)
        win.show()
        return int(app.exec())
    finally:
        if win is not None:
            win.stop_hotkeys()
        ls.stop_background()
