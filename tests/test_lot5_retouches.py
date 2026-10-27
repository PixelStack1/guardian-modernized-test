"""Lot 5 — retouches d'audit (G2-G5) et balayage fonctionnel de toute la GUI."""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from pathlib import Path  # noqa: E402

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QAbstractButton, QLabel, QLineEdit  # noqa: E402
from tests.gui_fakes import feed, make_session  # noqa: E402

from gui import core  # noqa: E402
from gui.window import MainWindow  # noqa: E402
from util.i18n import get_language, set_language  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def session(tmp_path):
    s = make_session(tmp_path)
    feed(s)
    return s


@pytest.fixture
def shown():
    return []


@pytest.fixture
def win(qtbot, session, shown):
    before = get_language()
    w = MainWindow(
        session,
        "3.7",
        ask_text=lambda *_a: "Toto",
        show_text=lambda _p, title, text: shown.append((title, text)),
    )
    w.timer.stop()
    qtbot.addWidget(w)
    yield w
    set_language(before, persist=False)


def click(qtbot, w):
    qtbot.mouseClick(w, Qt.MouseButton.LeftButton)


def select_ip(win, ip):
    t = win.live.table
    for i in range(t.rowCount()):
        if t.item(i, 0).data(Qt.ItemDataRole.UserRole) == ip:
            t.selectRow(i)
            return
    raise AssertionError(ip)


# -- G2 : texte d'aide du bouclier ------------------------------------------------
def test_g2_shield_help_opening_sentence():
    from util.i18n import STRINGS

    fr = STRINGS["gui.shield_help"]["fr"]
    assert fr.startswith(
        "Coupure si la moyenne dépasse le seuil sur le délai choisi ; "
        "inondations > 3× coupées plus vite."
    )
    assert STRINGS["gui.shield_help"]["en"].startswith(
        "Cut off when the average exceeds the threshold over the chosen delay"
    )


# -- recordings_directory : docstring = comportement (aucune création) -----------
def test_recordings_directory_does_not_create(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    class NoBox:
        blackbox = None

    d = core.recordings_directory(NoBox())
    assert d == tmp_path / "Guardian" / "enregistrements"
    assert not d.exists()


# -- G3 : avis LGPL PySide6 --------------------------------------------------------
def test_g3_notice_file_mentions_pyside6_lgpl():
    text = (ROOT / "guardian" / "THIRD_PARTY_NOTICES.txt").read_text(encoding="utf-8")
    assert "PySide6" in text and "LGPL-3.0" in text and "PySide6-Essentials" in text
    assert core.notice_path() == ROOT / "guardian" / "THIRD_PARTY_NOTICES.txt"
    assert "PySide6" in core.third_party_notice()


def test_g3_notice_path_frozen(monkeypatch, tmp_path):
    import sys

    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    assert core.notice_path() == tmp_path / "THIRD_PARTY_NOTICES.txt"
    assert "LGPL-3.0" in core.third_party_notice()  # repli si absent


def test_g3_about_button_shows_lgpl(qtbot, win, shown):
    click(qtbot, win.licences)
    assert len(shown) == 1
    title, text = shown[0]
    assert "licences" in title
    assert "PySide6" in text and "LGPL-3.0" in text


# -- G4 : exemples et démonstration en plages de documentation (RFC 5737) -------
def test_g4_demo_ips_are_documentation_ranges():
    import ipaddress

    from tests.gui_fakes import DEMO_PEERS

    doc = [
        ipaddress.ip_network(n)
        for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
    ]
    for ip, _pps, _ping in DEMO_PEERS:
        assert any(ipaddress.ip_address(ip) in n for n in doc), ip


# -- G5 : une notification = un seul affichage -------------------------------------
def test_g5_notify_fires_once(monkeypatch):
    import sys
    import types

    calls = []
    fake_ctypes = types.SimpleNamespace(
        windll=types.SimpleNamespace(
            user32=types.SimpleNamespace(
                MessageBoxW=lambda *a: calls.append(("box", a[1]))
            )
        )
    )
    src = (ROOT / "guardian" / "__main__.py").read_text(encoding="utf-8")
    start = src.index("def close_splash")
    end = src.index('if __name__ == "__main__":')
    ns = {
        "contextlib": __import__("contextlib"),
        "ctypes": fake_ctypes,
        "sys": sys,
        "CONSOLE_MODE": False,
        "print_white": lambda text: calls.append(("print", text)),
    }
    exec(src[start:end], ns)
    ns["notify"]("hello")
    assert calls == [("box", "hello")]
    calls.clear()
    ns["notify"]("hello", console=True)
    assert calls == [("print", "hello")]


def test_debug_logger_handler_not_shared():
    src = (ROOT / "guardian" / "__main__.py").read_text(encoding="utf-8")
    assert "\n    debug_logger.addHandler(fh)\n" in src
    assert "\ndebug_logger.addHandler(fh)\n" not in src


# -- Démarrage : build allégé ------------------------------------------------------
def test_build_args_lean_onefile_with_splash_and_notice():
    pytest.importorskip("PyInstaller")
    from guardian import build

    args = build.pyinstaller_args()
    assert "--onefile" in args and "--noupx" in args and "--windowed" in args
    splash = args[args.index("--splash") + 1]
    assert Path(splash).is_file()
    excluded = {args[i + 1] for i, a in enumerate(args) if a == "--exclude-module"}
    hidden = {args[i + 1] for i, a in enumerate(args) if a == "--hidden-import"}
    assert hidden == {"PySide6.QtCore", "PySide6.QtGui", "PySide6.QtWidgets"}
    assert not excluded & hidden
    for mod in ("QtNetwork", "QtQml", "QtWebEngineCore", "QtPdf", "QtOpenGL"):
        assert f"PySide6.{mod}" in excluded
    datas = [args[i + 1] for i, a in enumerate(args) if a == "--add-data"]
    for d in datas:
        assert Path(d.split(os.pathsep)[0]).is_file(), d
    assert any(d.endswith("THIRD_PARTY_NOTICES.txt" + os.pathsep + ".") for d in datas)
    assert any("geoip_ipv4.bin.gz" in d for d in datas)
    assert any("vpn_ipv4.bin.gz" in d for d in datas)


def test_only_qt_essentials_imported():
    import ast

    used = set()
    for f in (ROOT / "guardian").rglob("*.py"):
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
                "PySide6."
            ):
                used.add(node.module.split(".")[1])
    assert used <= {"QtCore", "QtGui", "QtWidgets"}, used


def test_pyproject_depends_on_essentials_only():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "PySide6-Essentials" in text
    assert "\nPySide6 = " not in text


def test_main_does_not_import_menu_at_top():
    src = (ROOT / "guardian" / "__main__.py").read_text(encoding="utf-8")
    head = src[: src.index('if __name__ == "__main__":')]
    assert "from menu.menu import Menu" not in head  # téléchargements à l'import


def test_startup_window_shows_immediately(qtbot):
    from gui.app import close_pyi_splash, startup_window

    close_pyi_splash()  # sans exe gelé : sans effet, sans exception
    w = startup_window("3.7")
    qtbot.addWidget(w)
    assert w.isVisible() and "Démarrage" in w.text()


# -- Balayage fonctionnel ----------------------------------------------------------
def test_every_button_is_connected(win):
    dead = [
        b.text() or b.objectName()
        for b in win.findChildren(QAbstractButton)
        # Pays de confiance par défaut : pastille d'information, non retirable.
        if "non retirable" not in b.toolTip()
        and not b.isSignalConnected(
            b.metaObject().method(b.metaObject().indexOfSignal("clicked(bool)"))
        )
    ]
    assert dead == []


def test_no_placeholder_text(win):
    bad = ("TODO", "Lorem", "placeholder", "FIXME", "XXX", "TBD")
    texts = [w.text() for w in win.findChildren(QLabel)] + [
        b.text() for b in win.findChildren(QAbstractButton)
    ]
    for t in texts:
        assert not any(m in t for m in bad), t
    for e in win.findChildren(QLineEdit):
        assert "TODO" not in e.placeholderText()


def test_every_sidebar_page(qtbot, win):
    for i, b in enumerate(win.nav):
        click(qtbot, b)
        assert win.stack.currentIndex() == i
        assert win.nav[i].isChecked()
        assert win.foot_left.text() == win.FOOT_LEFT[i]
        win.refresh()


@pytest.mark.parametrize(
    ("card", "attr"),
    [
        ("auto", "auto_block"),
        ("total", "total_block"),
        ("lock", "session_lock"),
        ("rec", "recording"),
        ("relay", "relay_block"),
    ],
)
def test_live_toggle_cards_change_state_and_refresh(qtbot, win, session, card, attr):
    before = getattr(core.take_snapshot(session), attr)
    c = getattr(win.live, card)
    click(qtbot, c.switch)
    after = getattr(core.take_snapshot(session), attr)
    assert after != before
    assert c.switch.isChecked() == after  # rafraîchi immédiatement


def test_kick_button_arms_capture(qtbot, win, session):
    n = len(session.ctrl.events)
    click(qtbot, win.live.kick)
    assert len(session.ctrl.events) == n + 1


def test_live_header_buttons(qtbot, win, session):
    ip = "203.0.113.10"
    select_ip(win, ip)
    click(qtbot, win.live.b_block)
    assert ip in session.blocked
    select_ip(win, ip)
    click(qtbot, win.live.b_unblock)
    assert ip not in session.blocked
    select_ip(win, ip)
    click(qtbot, win.live.b_friend)
    assert session.ctrl.is_friend(ip)
    select_ip(win, "203.0.113.110")
    click(qtbot, win.live.b_pseudo)  # pas d'exception, passe par la touche P


def test_buttons_without_selection_navigate(qtbot, win):
    win.live.table.clearSelection()
    click(qtbot, win.live.b_unblock)
    assert win.stack.currentIndex() == win.BLOCKED
    click(qtbot, win.live.b_friend)
    assert win.stack.currentIndex() == win.FRIENDS


def test_blocked_page_unblock(qtbot, win, session):
    ip = "192.0.2.160"
    win.actions_.block(ip)
    win.refresh()
    win.blocked.table.selectRow(0)
    click(qtbot, win.blocked.unblock)
    assert ip not in session.blocked
    assert win.blocked.table.rowCount() == 0


def test_friends_page_add_remove(qtbot, win, session):
    page = win.friends
    page.ip.setText("203.0.113.9")
    page.nick.setText("Bob")
    click(qtbot, page.add)
    assert session.ctrl.is_friend("203.0.113.9")
    ok_msg = page.message.text()
    assert ok_msg.startswith("Ami ajouté")
    page.ip.setText("pas une ip")
    click(qtbot, page.add)
    assert page.message.text() and page.message.text() != ok_msg
    page.list.setCurrentRow(0)
    click(qtbot, page.remove)
    assert not session.ctrl.is_friend("203.0.113.9")


@pytest.mark.parametrize(
    ("row", "key"),
    [
        ("shield_seconds", "shield_seconds"),
        ("shield_pps", "shield_pps"),
        ("ping", "ping_max_ms"),
        ("rate", "rate_limit_pps"),
        ("recording", "recording_seconds"),
    ],
)
def test_settings_sliders_persist(win, session, row, key):
    s = getattr(win.settings, row).slider
    saves = session.config.saves
    s.setValue(s.value() + 1 if s.value() < s.maximum() else s.value() - 1)
    assert session.config.saves == saves + 1
    assert getattr(win.actions_.settings(), key) == s.value()
    assert win.status.text() == "Réglages enregistrés"


def test_settings_switches_and_segments(qtbot, win, session):
    p = win.settings
    for sw, key in ((p.vpn_flag, "vpn_flag"), (p.vpn_block, "vpn_auto_block")):
        before = getattr(win.actions_.settings(), key)
        click(qtbot, sw)
        assert getattr(win.actions_.settings(), key) is (not before)
    s0 = session.ctrl.offender_sound
    click(qtbot, p.sound.switch)
    assert session.ctrl.offender_sound != s0
    c0 = session.ctrl.offender_drop
    click(qtbot, p.cut.switch)
    assert session.ctrl.offender_drop != c0
    click(qtbot, p.relay_block)
    assert session.ctrl.relay_block and p.relay_block.isChecked()
    click(qtbot, p.relay_allow)
    assert not session.ctrl.relay_block and p.relay_allow.isChecked()


def test_panic_switch_immediate(qtbot, win, session):
    click(qtbot, win.panic.switch)
    assert session.ctrl.panic and win.panic.switch.isChecked()
    click(qtbot, win.panic.switch)
    assert not session.ctrl.panic and not win.panic.switch.isChecked()


def test_language_persisted_in_session_config(qtbot, win, session):
    click(qtbot, win.lang_buttons[1])
    assert get_language() == "en" and session.config.data["language"] == "en"
    assert win.lang_buttons[1].isChecked()
    # Un réglage enregistré ensuite ne remet pas l'ancienne langue.
    win.settings.ping.slider.setValue(win.settings.ping.slider.value() + 1)
    assert session.config.data["language"] == "en"
    click(qtbot, win.settings.lang_fr)
    assert session.config.data["language"] == "fr"
    assert win.lang_buttons[0].isChecked()


def test_language_switch_does_not_touch_real_config(qtbot, win, monkeypatch):
    from config import configdata

    monkeypatch.setattr(
        configdata.ConfigData,
        "save",
        lambda self: (_ for _ in ()).throw(AssertionError("data.json réel")),
    )
    click(qtbot, win.lang_buttons[1])
    click(qtbot, win.lang_buttons[0])


def test_country_chip_remove(qtbot, win, session):
    p = win.settings
    p.country_in.setText("pl")
    click(qtbot, p.country_add)
    assert "PL" in win.actions_.settings().trusted_countries
    click(qtbot, p.chip_buttons["PL"])
    assert "PL" not in win.actions_.settings().trusted_countries


def test_files_pages_list_files(qtbot, win, session, tmp_path):
    (tmp_path / "kick-20261027-120000-test.csv").write_text("a\n")
    win.show_page(win.RECORDINGS)
    win.recordings.rescan()
    assert win.recordings.table.rowCount() == 1
    assert str(tmp_path) in win.recordings.where.text()
    win.show_page(win.REPORTS)
    win.reports.rescan()  # sans exception, même sans dossier


def test_shortcuts_all_bound(win):
    keys = sorted(sc.key().toString() for sc in win._keys)
    assert keys == sorted("ABCDEFKLPQSTVX")
