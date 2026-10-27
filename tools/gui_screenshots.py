"""Captures d'écran hors écran (offscreen) de la GUI avec une session factice.

Usage : QT_QPA_PLATFORM=offscreen python tools/gui_screenshots.py docs/screenshots
Aucune capture réseau : paquets factices (métadonnées) injectés dans la session.
"""

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ["LOCALAPPDATA"] = tempfile.mkdtemp(prefix="guardian-shots-")
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "guardian"), str(ROOT)]

from PySide6.QtWidgets import QApplication  # noqa: E402
from tests.gui_fakes import feed, make_session  # noqa: E402


def main(out: Path) -> None:
    from gui.window import MainWindow
    from menu import livesession as ls

    out.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication(sys.argv)
    session = make_session(Path(os.environ["LOCALAPPDATA"]))
    for _ in range(6):
        feed(session, seconds=0.5)
    for ip, n in (("192.81.241.171", 8), ("192.81.241.110", 3)):
        for k in range(n):
            session.monitor.add_packet(ip, 100, session.now - k / n, 6672)
    session.evaluate()
    win = MainWindow(session, "3.7", ask_text=lambda *_a: "Exemple")
    win.timer.stop()
    win.actions_.block("176.4.29.17", "Exemple")
    win.actions_.toggle_friend("85.214.132.89", "Ami")
    session.ctrl.offender_ips["177.54.148.23"] = 1.0
    session.ctrl.events.append(
        ls.t("live.ev.new_player", ip="85.214.132.89", country="DE")
    )
    win.actions_.toggle_lock()
    win.actions_.toggle_lock()
    for _ in range(30):
        win.live.spark.push(300 + (_ * 37) % 140)
    win.resize(1400, 860)
    win.show()
    for i, name in enumerate(["session", "bloques", "amis", "reglages"]):
        win.show_page(i)
        win.refresh()
        app.processEvents()
        win.grab().save(str(out / f"{i + 1:02d}-{name}.png"))
    win.close()


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "docs" / "screenshots"))
