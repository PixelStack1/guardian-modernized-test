"""Images côte à côte maquette | GUI (docs/compare/), même taille de fenêtre.

Usage : QT_QPA_PLATFORM=offscreen python tools/compare_mockup.py MAQUETTE_DIR
Rend index.html (vues session et réglages) avec Chrome headless à 1440×900,
recadre la zone utile de la fenêtre (1398×816 sous la barre de titre) et la
place à gauche de la capture GUI correspondante (docs/screenshots).
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = Path(__file__).resolve().parents[1]

from PySide6.QtCore import QRect, Qt  # noqa: E402
from PySide6.QtGui import QColor, QFont, QGuiApplication, QImage, QPainter  # noqa: E402

BODY = QRect(21, 63, 1398, 816)  # .window à (20,20) + bordure 1 px + barre 42 px
PAIRS = [("session", "01-session"), ("reglages", "04-reglages")]
ZOOMS = {"haut": QRect(0, 0, 1398, 220), "barre-laterale": QRect(0, 0, 220, 816)}


def render(mock: Path, view: str, out: Path) -> QImage:
    html = (mock / "index.html").read_text(encoding="utf-8")
    html = html.replace('<body data-view="session">', f'<body data-view="{view}">')
    tmp = Path(tempfile.mkdtemp()) / "index.html"
    tmp.write_text(html, encoding="utf-8")
    chrome = shutil.which("google-chrome") or "chromium"
    subprocess.run(
        [
            chrome,
            "--headless=new",
            "--no-sandbox",
            "--hide-scrollbars",
            "--window-size=1440,900",
            f"--screenshot={out}",
            tmp.as_uri(),
        ],
        check=True,
        capture_output=True,
    )
    return QImage(str(out)).copy(BODY)


def side_by_side(left: QImage, right: QImage, title: str) -> QImage:
    gap, head = 16, 34
    w = left.width() + right.width() + gap
    h = max(left.height(), right.height()) + head
    img = QImage(w, h, QImage.Format.Format_RGB32)
    img.fill(QColor("#05070c"))
    p = QPainter(img)
    f = QFont()
    f.setPixelSize(16)
    f.setBold(True)
    p.setFont(f)
    p.setPen(QColor("#e8eef8"))
    p.drawText(
        QRect(0, 0, left.width(), head),
        Qt.AlignmentFlag.AlignCenter,
        f"MAQUETTE — {title}",
    )
    p.drawText(
        QRect(left.width() + gap, 0, right.width(), head),
        Qt.AlignmentFlag.AlignCenter,
        f"GUI PySide6 — {title}",
    )
    p.drawImage(0, head, left)
    p.drawImage(left.width() + gap, head, right)
    p.end()
    return img


def stacked(top: QImage, bottom: QImage, scale: int = 2) -> QImage:
    a = top.scaled(top.width() * scale, top.height() * scale)
    b = bottom.scaled(bottom.width() * scale, bottom.height() * scale)
    img = QImage(
        max(a.width(), b.width()),
        a.height() + b.height() + 12,
        QImage.Format.Format_RGB32,
    )
    img.fill(QColor("#ff00ff"))
    p = QPainter(img)
    p.drawImage(0, 0, a)
    p.drawImage(0, a.height() + 12, b)
    p.end()
    return img


def main(mock: Path) -> None:
    _app = QGuiApplication.instance() or QGuiApplication(sys.argv)
    out = ROOT / "docs" / "compare"
    out.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp())
    for view, shot in PAIRS:
        m = render(mock, view, tmp / f"{view}.png")
        m.save(str(out / f"maquette-{view}.png"))
        g = QImage(str(ROOT / "docs" / "screenshots" / f"{shot}.png"))
        side_by_side(m, g, view).save(str(out / f"{shot}-maquette-vs-gui.png"))
        if view == "session":
            for name, r in ZOOMS.items():
                img = (
                    stacked(m.copy(r), g.copy(r))
                    if name == "haut"
                    else side_by_side(m.copy(r), g.copy(r), name)
                )
                img.save(str(out / f"zoom-{name}-maquette-vs-gui.png"))


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "/workspace/guardian-ui-mockup"))
