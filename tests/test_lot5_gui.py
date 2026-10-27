"""Lot 5 — GUI PySide6 (offscreen) : widgets, bascules = mêmes fonctions que la console."""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from PySide6.QtCore import Qt  # noqa: E402
from tests.gui_fakes import FakeConfig, feed, make_session  # noqa: E402

from gui import core  # noqa: E402
from gui.window import MainWindow  # noqa: E402
from menu import livesession as ls  # noqa: E402


@pytest.fixture
def session(tmp_path):
    s = make_session(tmp_path)
    feed(s)
    return s


@pytest.fixture
def win(qtbot, session):
    w = MainWindow(session, "3.7", ask_text=lambda *_a: "Toto")
    w.timer.stop()
    qtbot.addWidget(w)
    return w


@pytest.fixture
def keys(monkeypatch):
    """Espionne handle_key : chaque action GUI doit passer par la touche console."""
    calls = []
    real = ls.handle_key

    def spy(key, *a, **kw):
        calls.append(key)
        return real(key, *a, **kw)

    monkeypatch.setattr(ls, "handle_key", spy)
    return calls


def select_ip(win, ip):
    t = win.live.table
    for i in range(t.rowCount()):
        if t.item(i, 0).data(Qt.ItemDataRole.UserRole) == ip:
            t.selectRow(i)
            return
    raise AssertionError(ip)


def test_table_shows_peers_with_country_ping_pps(win, session):
    t = win.live.table
    assert t.rowCount() == len(session.peers) > 0  # aucun serveur R* ici
    ips = {t.item(i, 1).text() for i in range(t.rowCount())}
    assert "82.64.12.45" in ips
    row = next(i for i in range(t.rowCount()) if t.item(i, 1).text() == "82.64.12.45")
    assert t.item(row, 0).text() == "France"
    assert t.item(row, 2).text().endswith("ms")
    assert float(t.item(row, 3).text()) > 0
    assert "NOUVEAU" in t.item(row, 5).text()


@pytest.mark.parametrize(
    ("card", "key", "attr"),
    [
        ("auto", "a", "auto_block"),
        ("total", "t", "total_block"),
        ("lock", "v", "session_lock"),
        ("relay", "l", "relay_block"),
        ("panic", "x", "panic"),
        ("sound", "s", "offender_sound"),
        ("cut", "c", "offender_drop"),
    ],
)
def test_toggle_cards_call_console_keys(qtbot, win, session, keys, card, key, attr):
    before = bool(getattr(session.ctrl, attr))
    widget = getattr(win.live, card)
    qtbot.mouseClick(widget.switch, Qt.MouseButton.LeftButton)
    assert keys == [key]
    assert bool(getattr(session.ctrl, attr)) is (not before)
    win.refresh()
    assert widget.switch.isChecked() is (not before)
    assert widget.pill.text() in ("ACTIVÉ", "DÉSACTIVÉ", "BLOQUÉ", "AUTORISÉ")


def test_toggle_persists_like_console(qtbot, win, session):
    qtbot.mouseClick(win.live.total.switch, Qt.MouseButton.LeftButton)
    assert session.config.data[ls.TOTAL_BLOCK_KEY] is session.ctrl.total_block
    assert session.config.saves >= 1


def test_status_shows_only_latest_message_green_red(qtbot, win, session):
    qtbot.mouseClick(win.live.lock.switch, Qt.MouseButton.LeftButton)
    win.refresh()
    first = win.status.text()
    assert first and win.status.objectName() == "statusOk"
    qtbot.mouseClick(win.live.lock.switch, Qt.MouseButton.LeftButton)
    win.refresh()
    assert win.status.text() != first
    assert "\n" not in win.status.text()
    assert win.status.objectName() == "statusBad"
    assert "\x1b" not in win.status.text()


def test_recording_and_kick_buttons(qtbot, win, session, keys):
    qtbot.mouseClick(win.live.rec.switch, Qt.MouseButton.LeftButton)
    assert session.recorder.active
    qtbot.mouseClick(win.live.kick, Qt.MouseButton.LeftButton)
    assert keys == ["e", "k"]


def test_block_unblock_selected_row(qtbot, win, session, keys):
    select_ip(win, "91.198.174.22")
    qtbot.mouseClick(win.live.b_block, Qt.MouseButton.LeftButton)
    assert "91.198.174.22" in session.blocked
    assert session.ctrl.blacklist.get("91.198.174.22") is not None
    select_ip(win, "91.198.174.22")
    qtbot.mouseClick(win.live.b_unblock, Qt.MouseButton.LeftButton)
    assert "91.198.174.22" not in session.blocked
    assert keys == ["b", "d"]


def test_blocked_page_unblock(qtbot, win, session, keys):
    win.actions_.block("85.214.132.89", "x")
    win.refresh()
    page = win.blocked
    assert page.table.rowCount() == 1
    page.table.selectRow(0)
    qtbot.mouseClick(page.unblock, Qt.MouseButton.LeftButton)
    assert "85.214.132.89" not in session.blocked
    assert keys == ["b", "d"]


def test_friend_toggle_and_friends_page(qtbot, win, session, keys):
    select_ip(win, "79.23.45.110")
    qtbot.mouseClick(win.live.b_friend, Qt.MouseButton.LeftButton)
    assert session.ctrl.friends.get("79.23.45.110") == "Toto"
    assert session.config.data[ls.FRIENDS_KEY] == {"79.23.45.110": "Toto"}
    win.refresh()
    assert win.friends.list.count() == 1
    win.friends.list.setCurrentRow(0)
    qtbot.mouseClick(win.friends.remove, Qt.MouseButton.LeftButton)
    assert "79.23.45.110" not in session.ctrl.friends
    win.friends.ip.setText("pas-une-ip")
    qtbot.mouseClick(win.friends.add, Qt.MouseButton.LeftButton)
    assert not session.ctrl.friends
    win.friends.ip.setText("81.2.69.160")
    win.friends.nick.setText("Ami")
    qtbot.mouseClick(win.friends.add, Qt.MouseButton.LeftButton)
    assert session.ctrl.friends == {"81.2.69.160": "Ami"}
    assert keys == ["f"]


def test_keyboard_shortcuts_match_console(win, session, keys):
    """Mêmes lettres que la console : chaque raccourci déclenche la même touche."""
    by_key = {sc.key().toString(): sc for sc in win._keys}
    for k in "ATVLXSCKE":
        by_key[k].activated.emit()
    assert keys == list("atvlxscke")
    assert {"B", "D", "F", "P"} <= set(by_key)


def test_rockstar_block_refused(win, session):
    session.monitor.add_packet("192.81.241.171", 100, session.now, 6672)
    session.evaluate()
    win.refresh()
    win.actions_.block("192.81.241.171")
    assert "192.81.241.171" not in session.blocked


def test_settings_page_writes_all_data_json_values(qtbot, win, session):
    page = win.settings
    page.shield_seconds.slider.setValue(5)
    page.shield_pps.slider.setValue(80)
    page.ping.slider.setValue(150)
    page.rate.slider.setValue(60)
    page.recording.slider.setValue(30)
    page.vpn_block.click()
    page.country_in.setText("de")
    qtbot.mouseClick(page.country_add, Qt.MouseButton.LeftButton)
    d = session.config.data
    assert d["shield_seconds"] == 5.0
    assert d["shield_pps"] == 80
    assert d["ping_max_ms"] == 150.0
    assert d["rate_limit_pps"] == 60
    assert d["recording_seconds"] == 30
    assert d["vpn_auto_block"] is True
    assert d["vpn_flag"] is True
    assert "DE" in d["trusted_countries"]
    # Appliqué immédiatement à la session.
    assert session.monitor.shield_pps == 80
    assert session.ctrl.filters.settings.ping_max_ms == 150.0
    assert session.ctrl.filters.settings.vpn_auto_block is True
    assert session.blackbox.seconds == 30


def test_settings_relay_segment_uses_l(qtbot, win, session, keys):
    qtbot.mouseClick(win.settings.relay_block, Qt.MouseButton.LeftButton)
    assert session.ctrl.relay_block
    qtbot.mouseClick(win.settings.relay_block, Qt.MouseButton.LeftButton)
    assert keys == ["l"]  # déjà bloqué : pas de second basculement


def test_settings_invalid_values_are_clamped():
    s = core.Settings(
        trusted_countries=["fr", "xx1", 3, "BE"],
        ping_max_ms=150,
        rate_limit_pps=60,
        shield_pps=5,
        shield_seconds=999,
        recording_seconds=0,
    )
    session = make_session(None, FakeConfig())
    out = core.GuiActions(session).apply_settings(s)
    assert out.shield_pps == 20 and out.shield_seconds == 60.0
    assert out.recording_seconds == 1
    assert session.config.data["trusted_countries"] == ["FR", "BE"]


def test_snapshot_is_plain_data_and_never_touches_capture(session):
    snap = core.take_snapshot(session)
    assert snap.players == len(snap.rows)
    assert all(isinstance(r, core.Row) for r in snap.rows)
    # Lire n'a consommé aucun paquet ni appelé la capture.
    assert session.packets.empty()


def test_action_error_is_reported_not_raised(win, session, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("x")

    monkeypatch.setattr(ls, "handle_key", boom)
    win.actions_.toggle_auto()
    assert session.ctrl.events[-1]


def test_navigation_pages(qtbot, win):
    for i, b in enumerate(win.nav):
        qtbot.mouseClick(b, Qt.MouseButton.LeftButton)
        assert win.stack.currentIndex() == i


def test_console_flag_keeps_console_mode():
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "guardian_main_mod", Path(__file__).parents[1] / "guardian" / "__main__.py"
    )
    src = Path(spec.origin).read_text(encoding="utf-8")
    assert '"--console"' in src and "Menu.main_menu()" in src and "run_gui" in src


def test_row_buttons_block_and_unblock(qtbot, win, session, keys):
    btn = win.live.row_button("91.198.174.22")
    assert btn is not None and btn.text() == "Bloquer"
    qtbot.mouseClick(btn, Qt.MouseButton.LeftButton)
    assert "91.198.174.22" in session.blocked
    btn = win.live.row_button("91.198.174.22")
    assert btn.text() == "Débloquer"
    qtbot.mouseClick(btn, Qt.MouseButton.LeftButton)
    assert "91.198.174.22" not in session.blocked
    assert keys == ["b", "d"]


def test_flag_and_full_country_name(win):
    t = win.live.table
    row = next(i for i in range(t.rowCount()) if t.item(i, 1).text() == "82.64.12.45")
    assert t.item(row, 0).text() == "France"
    assert not t.item(row, 0).icon().isNull()


def test_rockstar_servers_in_separate_block(win, session):
    session.monitor.add_packet("192.81.241.171", 100, session.now, 6672)
    session.evaluate()
    win.refresh()
    t = win.live.table
    assert "192.81.241.171" not in {t.item(i, 1).text() for i in range(t.rowCount())}
    assert win.live.servers.item(0, 0).text() == "192.81.241.171"


def test_country_chips_add_remove(qtbot, win, session):
    page = win.settings
    assert "FR" in page.chip_buttons
    page.country_in.setText("de")
    qtbot.mouseClick(page.country_add, Qt.MouseButton.LeftButton)
    assert (
        "DE" in page.chip_buttons and "DE" in session.config.data["trusted_countries"]
    )
    qtbot.mouseClick(page.chip_buttons["DE"], Qt.MouseButton.LeftButton)
    assert "DE" not in session.config.data["trusted_countries"]
    assert "DE" not in page.chip_buttons
    qtbot.mouseClick(page.chip_buttons["FR"], Qt.MouseButton.LeftButton)
    assert "FR" in page.chip_buttons  # défaut non retirable


def test_relay_allowed_is_green(win):
    win.refresh()
    assert win.live.relay.pill.text() == "AUTORISÉ"
    assert win.live.relay.pill.objectName() == "pillOn"
