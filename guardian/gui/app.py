"""Lancement de la GUI : session en fond (capture dans son processus), fenêtre Qt.

Démarrage : l'écran PyInstaller (``--splash``) couvre la décompression de l'exe ;
dès que Qt est chargé, une petite fenêtre « Démarrage… » le remplace pendant la
création de la session (téléchargement des plages, pilote), puis la fenêtre
principale s'affiche.
"""

from __future__ import annotations

import contextlib
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


def close_pyi_splash() -> None:
    """Ferme l'écran de démarrage PyInstaller s'il existe (exe gelé)."""
    with contextlib.suppress(Exception):
        import importlib

        importlib.import_module("pyi_splash").close()


def startup_window(version: str = "") -> Any:
    """Fenêtre légère affichée immédiatement (aucune dépendance au réseau)."""
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QLabel

    w = QLabel(f"Guardian {version}\nDémarrage de la protection…".replace("  ", " "))
    w.setObjectName("startup")
    w.setAlignment(Qt.AlignmentFlag.AlignCenter)
    w.setWindowFlags(Qt.WindowType.SplashScreen | Qt.WindowType.WindowStaysOnTopHint)
    w.setStyleSheet(
        "QLabel#startup { background: #0b1220; color: #e6edf7; font-size: 14px;"
        " padding: 24px; border: 1px solid #22d3ee; }"
    )
    w.resize(340, 110)
    w.show()
    QApplication.processEvents()
    return w


def run_gui(
    factory: Callable[[], Any] | None = None,
    version: str = "",
    on_shutdown: Callable[[], Any] | None = None,
) -> int:  # pragma: no cover - interactif, Windows
    from PySide6.QtGui import QGuiApplication
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication(sys.argv)
    splash = startup_window(version)
    close_pyi_splash()

    from gui.window import MainWindow
    from menu import livesession as ls

    # Lot 7 : arrêt propre aussi à la fin de session Windows (aboutToQuit).
    app.aboutToQuit.connect(ls.stop_background)
    if isinstance(app, QGuiApplication):
        app.commitDataRequest.connect(lambda _m: session_end_cleanup(on_shutdown))
    win = None
    try:
        session = ls.attach_or_start(factory or ls._create_session)
        app.processEvents()
        win = MainWindow(session, version, global_hotkeys=True)
        win.show()
        splash.close()
        return int(app.exec())
    finally:
        splash.close()
        if win is not None:
            win.stop_hotkeys()
        ls.stop_background()
