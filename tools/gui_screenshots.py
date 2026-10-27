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
    for p in (
        session.monitor.peers.values() if hasattr(session.monitor, "peers") else []
    ):
        p.first_seen -= 120  # fin de la période d'apprentissage (capture seulement)
    session.evaluate()
    # Exemples (dossier temporaire de la capture uniquement).
    from network.incident import reports_dir

    rep = reports_dir()
    rep.mkdir(parents=True, exist_ok=True)
    for name in ("20261027-142201_176.4.29.17", "20261027-150512_177.54.148.23"):
        (rep / f"{name}.txt").write_text("Rapport d'incident (exemple)\n" * 40)
        (rep / f"{name}.json").write_text("{}")
    rec = Path(os.environ["LOCALAPPDATA"])
    for name in ("kick-20261027-142205-kick", "kick-20261027-150530-manuel"):
        (rec / f"{name}.csv").write_text("ts,ip,size\n" + "0,0.0.0.0,0\n" * 300)
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
    for k in range(120):  # historique 60 s (sinon courbe/mini-barres vides)
        win.live.spark.push(380 + (k * 37) % 90 + (160 if 70 < k < 80 else 0))
    for n, (_ip, h) in enumerate(win.live.history.items()):
        last = h[-1] if h else 10.0
        h.clear()
        for k in range(9):
            h.append(last * (0.75 + ((k * 7 + n * 3) % 6) / 20))
    # Zone utile de la maquette : 1400×860 moins bordure (1 px) et barre de titre
    # (42 px) = 1398×816 ; la barre native de Windows remplace la barre dessinée.
    win.resize(1398, 816)
    win.show()
    pages = [
        (win.LIVE, "session"),
        (win.BLOCKED, "bloques"),
        (win.FRIENDS, "amis"),
        (win.SETTINGS, "reglages"),
        (win.REPORTS, "rapports"),
        (win.RECORDINGS, "enregistrements"),
    ]
    for i, (page, name) in enumerate(pages):
        win.show_page(page)
        win.refresh()
        app.processEvents()
        win.grab().save(str(out / f"{i + 1:02d}-{name}.png"))
    win.close()


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "docs" / "screenshots"))
