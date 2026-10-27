"""Lancement de la GUI : session en fond (capture dans son processus), fenêtre Qt."""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import Any


def run_gui(
    factory: Callable[[], Any] | None = None, version: str = ""
) -> int:  # pragma: no cover - interactif, Windows
    from PySide6.QtWidgets import QApplication

    from gui.window import MainWindow
    from menu import livesession as ls

    app = QApplication.instance() or QApplication(sys.argv)
    session = ls.attach_or_start(factory or ls._create_session)
    try:
        win = MainWindow(session, version)
        win.show()
        return int(app.exec())
    finally:
        ls.stop_background()
