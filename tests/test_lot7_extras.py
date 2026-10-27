"""Lot 7 — extras : amis, profils, raccourcis globaux + arrêt d'urgence, arrêt
propre du pilote, diagnostic au démarrage, SHA256 de l'exécutable."""

import hashlib
import json
import os
import threading

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from tests.gui_fakes import FakeConfig, FakeList, feed, make_session
from tests.test_totalblock import FakeHandle, FakePacket

from menu import livesession as ls
from util import exehash, health
from util.driver import CTRL_CLOSE_EVENT, DriverLifecycle
from util.hotkeys import DEFAULT_HOTKEYS, GlobalHotkeys, hotkey_text
from util.i18n import t

FRIEND = "192.0.2.160"
OTHER = "203.0.113.22"


class Flag:
    def __init__(self):
        self.value = 0


def ctrl(blacklist=None, **kw):
    return ls.LiveSessionController(
        {}, blacklist if blacklist is not None else FakeList(), sound=lambda: None, **kw
    )


# -- 1) amis ----------------------------------------------------------------------
def test_friend_never_dropped_even_if_blocked_panic_or_lock():
    policy = ls.LivePolicy(friends=frozenset({FRIEND}), panic=True, lock_on=True)
    w = FakeHandle()
    blocked = {FRIEND: ls.PERMANENT, OTHER: ls.PERMANENT}
    total = {FRIEND: 9e12}
    assert ls.handle_packet(
        w,
        FakePacket(FRIEND, "10.0.0.2", True),
        blocked,
        total,
        1.0,
        True,
        False,
        policy,
    )
    assert ls.handle_packet(
        w,
        FakePacket("10.0.0.2", FRIEND, False),
        blocked,
        total,
        1.0,
        True,
        False,
        policy,
    )
    assert not ls.handle_packet(
        w, FakePacket(OTHER, "10.0.0.2", True), blocked, total, 1.0, True, False, policy
    )
    assert len(w.sent) == 2


def test_friend_cannot_be_blocked_manually_or_auto():
    c = ctrl()
    c.add_friend(FRIEND, "Ami")
    c.block(FRIEND)
    assert FRIEND not in c.blocked
    assert any("liste d'amis" in e for e in c.events)
    peer = ls.PeerState(ip=FRIEND, first_seen=0.0, last_seen=0.0)
    peer.level = ls.Level.SUSPECT
    assert not c.auto_block_if_needed(peer)


def test_friend_in_saved_blacklist_not_blocked_at_start():
    bl = FakeList({FRIEND: "x", OTHER: "y"})
    c = ctrl(bl, friends={FRIEND: "Ami"})
    assert FRIEND not in c.blocked and OTHER in c.blocked


def test_adding_friend_unblocks():
    c = ctrl()
    c.blocked[FRIEND] = ls.PERMANENT
    assert c.add_friend(FRIEND, "Ami")
    assert FRIEND not in c.blocked


# -- 3) arrêt d'urgence ----------------------------------------------------------
def test_bypass_sends_every_original_packet():
    w = FakeHandle()
    policy = ls.LivePolicy(panic=True)
    p = FakePacket(OTHER, "10.0.0.2", True)
    assert ls.handle_packet(
        w, p, {OTHER: ls.PERMANENT}, {}, 1.0, True, True, policy, True
    )
    assert w.sent == [p]


def test_broken_packet_passes():
    class Broken:
        @property
        def is_inbound(self):
            raise RuntimeError

    w = FakeHandle()
    assert ls.handle_packet(w, Broken(), {}, {}, 1.0, policy=ls.LivePolicy(panic=True))


def test_emergency_stop_lifts_everything_and_resume_restores_saved():
    bl = FakeList({OTHER: "y"})
    flag, panic, lock = Flag(), Flag(), Flag()
    c = ctrl(
        bl, bypass_flag=flag, panic_flag=panic, lock_flag=lock, clock=lambda: 100.0
    )
    c.auto_entries["192.0.2.5"] = 1000.0
    c.blocked["192.0.2.5"] = 1000.0
    c.blocked["192.0.2.6"] = ls.PERMANENT
    c.panic = True
    c.session_lock = True
    c.emergency_stop()
    assert c.filtering_paused and flag.value
    assert not c.blocked and not c.panic and not c.session_lock and not c.auto_block
    assert panic.value == 0 and lock.value == 0
    assert dict(bl) == {OTHER: "y"}  # data.json intact
    peer = ls.PeerState(ip="192.0.2.7", first_seen=0.0, last_seen=0.0)
    peer.level = ls.Level.SUSPECT
    c.auto_block = True
    assert not c.auto_block_if_needed(peer)  # aucun nouveau blocage pendant l'urgence
    c.toggle_emergency()
    assert not c.filtering_paused and not flag.value
    assert c.blocked == {OTHER: ls.PERMANENT, "192.0.2.5": 1000.0}


# -- 2) profils ------------------------------------------------------------------
@pytest.mark.parametrize("key", ["solo", "friends", "public"])
def test_profiles_apply_and_persist(tmp_path, key):
    from gui.profiles import PROFILES, apply_profile, current_profile

    s = make_session(tmp_path)
    assert apply_profile(s, key)
    p, c = PROFILES[key], s.ctrl
    assert (c.panic, c.session_lock, c.auto_block, c.total_block, c.offender_drop) == (
        p.panic,
        p.session_lock,
        p.auto_block,
        p.total_block,
        p.offender_drop,
    )
    assert s.config.data[ls.SESSION_LOCK_KEY] == p.session_lock
    assert s.config.data[ls.TOTAL_BLOCK_KEY] == p.total_block
    assert current_profile(c) == key


def test_profile_and_toggles_blocked_during_emergency(tmp_path):
    from gui.profiles import PROFILES, apply_profile

    s = make_session(tmp_path)
    c = s.ctrl
    before = (c.panic, c.session_lock, c.auto_block, c.total_block, c.offender_drop)
    c.emergency_stop()
    assert not apply_profile(s, "public")
    for k in "atvxc":
        ls.handle_key(k, c, [], s.blocked, s.recorder, lambda _t: "", s.config)
    assert (c.panic, c.session_lock, c.auto_block, c.total_block, c.offender_drop) == (
        False,
        False,
        False,
        False,
        False,
    )
    assert c.filtering_paused
    assert c.toggle_msg and c.toggle_msg[0] == t("live.ev.paused_locked")
    c.resume_filtering()
    after = (c.panic, c.session_lock, c.auto_block, c.total_block, c.offender_drop)
    assert after == before  # rien n'a été écrasé
    assert apply_profile(s, "public")
    assert c.panic == PROFILES["public"].panic
    assert not apply_profile(s, "inconnu")


# -- raccourcis globaux -----------------------------------------------------------
class FakeApi:
    def __init__(self, taken=()):
        self.taken = set(taken)
        self.events = []
        self.unregistered = []
        self.cv = threading.Condition()
        self.quit = False

    def register(self, hid, mods, vk):
        return vk not in self.taken

    def unregister(self, hid):
        self.unregistered.append(hid)

    def next_hotkey(self):
        with self.cv:
            self.cv.wait_for(lambda: self.events or self.quit, timeout=5)
            if self.quit:
                return None
            return self.events.pop(0)

    def press(self, hid):
        with self.cv:
            self.events.append(hid)
            self.cv.notify_all()

    def wake(self, _tid):
        with self.cv:
            self.quit = True
            self.cv.notify_all()


def test_global_hotkeys_thread_dispatch_and_cleanup():
    api = FakeApi(taken={ord("T")})
    got = []
    done = threading.Event()
    hk = GlobalHotkeys(lambda a: (got.append(a), done.set()), api_factory=lambda: api)
    assert hk.start() == ["total"]
    api.press(1)
    assert done.wait(2)
    assert got == ["emergency"]
    hk.stop()
    assert sorted(api.unregistered) == [1, 2, 3, 5]
    assert hotkey_text("emergency") == "Ctrl+Alt+F12"


def test_global_hotkeys_unsupported_off_windows(monkeypatch):
    monkeypatch.setattr("sys.platform", "linux")
    hk = GlobalHotkeys(lambda a: None)
    assert hk.start() == [h.action for h in DEFAULT_HOTKEYS]
    hk.stop()


# -- 4) arrêt propre du pilote ----------------------------------------------------
class FakeWD:
    def __init__(self, registered=False):
        self.registered = registered
        self.calls = []

    def is_registered(self):
        return self.registered

    def register(self):
        self.calls.append("register")

    def unregister(self):
        self.calls.append("unregister")


def test_driver_closes_our_handle_before_unregister():
    wd = FakeWD()
    d = DriverLifecycle(wd)
    d.start()
    order = []
    d.add_pre_cleanup(lambda: order.append(wd.calls[:]))
    d.add_pre_cleanup(lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert d.console_event(CTRL_CLOSE_EVENT) is False
    d.cleanup()  # idempotent
    assert order == [["register"]]
    assert wd.calls == ["register", "unregister"]
    assert d.steps[-1] == "unregister"


def test_driver_leaves_foreign_driver_and_installs_handler():
    wd = FakeWD(registered=True)
    d = DriverLifecycle(wd)
    d.start()

    class K32:
        def SetConsoleCtrlHandler(self, fn, add):
            self.fn = fn
            return 1

    k = K32()
    assert d.install_console_handler(k)
    k.fn(CTRL_CLOSE_EVENT)
    assert wd.calls == []


# -- 5) diagnostic -----------------------------------------------------------------
def test_health_checks(tmp_path):
    good = tmp_path / "data.json"
    good.write_text(json.dumps({"blacklist": {}}))
    checks = health.run_checks(lambda: True, lambda: {}, good)
    assert [c.ok for c in checks] == [True, True, True]
    bad = tmp_path / "bad.json"
    bad.write_text("{pas du json")

    def boom():
        raise RuntimeError("WinDivert64.sys is missing")

    checks = health.run_checks(lambda: False, boom, bad)
    assert [c.ok for c in checks] == [False, False, False]
    assert "missing" in checks[1].detail
    assert health.problems(checks) == 3
    assert health.check_admin(lambda: None).ok is None
    assert health.check_config(tmp_path / "absent.json").ok is True
    assert checks[0].state() == "ÉCHEC"


# -- 6) SHA256 de l'exe -------------------------------------------------------------
def test_exe_hash(tmp_path):
    exe = tmp_path / "Guardian.exe"
    exe.write_bytes(b"MZ" * 1000)
    info = exehash.compute(exe, True)
    assert info.sha256 == hashlib.sha256(b"MZ" * 1000).hexdigest()
    assert exehash.compute(exe, False).sha256 == ""
    assert exehash.compute(tmp_path / "x.exe", True).error


# -- GUI ---------------------------------------------------------------------------
pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")


@pytest.fixture
def gui(qtbot, tmp_path):
    from gui.window import MainWindow

    s = make_session(tmp_path, FakeConfig({"language": "fr"}))
    feed(s)
    api = FakeApi(taken={ord("V")})
    checks = health.run_checks(lambda: False, lambda: {}, tmp_path / "absent.json")
    exe = exehash.ExeHash("C:/Guardian.exe", "ab" * 32, True)
    w = MainWindow(
        s,
        "3.7",
        ask_text=lambda *_a: "Toto",
        hotkey_api=lambda: api,
        checks=checks,
        exe=exe,
    )
    w.timer.stop()
    qtbot.addWidget(w)
    yield w, s, api
    w.stop_hotkeys()


def test_gui_settings_show_health_hash_hotkeys(gui):
    w, _s, _api = gui
    st = w.settings
    assert st.exe_hash.text() == "ab" * 32
    assert "ÉCHEC" in st.health_rows[0].text()
    assert "Droits administrateur" in st.health_rows[0].text()
    assert "Ctrl+Alt+F12" in st.hotkeys_text.text()
    assert "déjà utilisé" in st.hotkeys_text.text()
    assert "1 problème" in w.status.text()


def test_gui_profile_buttons(gui, qtbot):
    from PySide6.QtCore import Qt

    w, s, _api = gui
    qtbot.mouseClick(w.settings.profile_buttons["solo"], Qt.MouseButton.LeftButton)
    assert s.ctrl.panic and s.ctrl.total_block
    assert w.settings.profile_buttons["solo"].isChecked()
    assert w.panic.switch.isChecked()
    qtbot.mouseClick(w.settings.profile_buttons["public"], Qt.MouseButton.LeftButton)
    assert not s.ctrl.panic and not s.ctrl.session_lock


def test_gui_global_hotkey_emergency_and_switch(gui, qtbot):
    w, s, api = gui
    s.ctrl.block(OTHER)
    api.press(1)  # Ctrl+Alt+F12 depuis le fil des raccourcis
    qtbot.waitUntil(lambda: s.ctrl.filtering_paused, timeout=2000)
    w.refresh()
    assert not s.ctrl.blocked
    assert w.emergency.switch.isChecked()
    assert "FILTRAGE SUSPENDU" in w.status.text()
    w.emergency.switch.click()
    assert not s.ctrl.filtering_paused
    assert OTHER in s.ctrl.blocked  # liste noire enregistrée rétablie


def test_gui_friends_page_texts_and_unblock(gui, qtbot):
    from PySide6.QtCore import Qt

    w, s, _api = gui
    s.ctrl.block(FRIEND)
    w.friends.ip.setText(FRIEND)
    w.friends.nick.setText("Ami")
    qtbot.mouseClick(w.friends.add, Qt.MouseButton.LeftButton)
    assert FRIEND not in s.ctrl.blocked
    assert "Ami ajouté" in w.friends.message.text()
    assert w.friends.meta.text() == "1 ami(s)"
    w.friends.list.setCurrentRow(0)
    qtbot.mouseClick(w.friends.remove, Qt.MouseButton.LeftButton)
    assert w.friends.message.text() == "Ami retiré."


# -- correctifs d'audit (R1-R4) -------------------------------------------------
def test_r1_emergency_restores_exact_toggles_and_data_json(tmp_path):
    from gui.profiles import toggle_emergency

    s = make_session(tmp_path)
    c = s.ctrl
    c.panic, c.session_lock, c.offender_drop, c.auto_block, c.total_block = (
        True,
        True,
        True,
        True,
        True,
    )
    before = dict(s.config.data)
    assert toggle_emergency(s)
    assert c.filtering_paused
    assert not any(
        (c.panic, c.session_lock, c.offender_drop, c.auto_block, c.total_block)
    )
    assert s.config.data == before  # data.json jamais modifié pendant l'arrêt
    c.emergency_stop()  # second appel : l'instantané d'origine est conservé
    assert toggle_emergency(s)
    assert (c.panic, c.session_lock, c.offender_drop, c.auto_block, c.total_block) == (
        True,
        True,
        True,
        True,
        True,
    )
    assert s.config.data[ls.SESSION_LOCK_KEY] is True
    assert s.config.data[ls.AUTO_BLOCK_KEY] is True
    assert s.config.data[ls.TOTAL_BLOCK_KEY] is True
    assert s.config.data[ls.OFFENDER_DROP_KEY] is True


def test_r1_emergency_keeps_off_toggles_off(tmp_path):
    from gui.profiles import toggle_emergency

    s = make_session(tmp_path)
    c = s.ctrl
    c.auto_block, c.total_block, c.panic = True, False, False
    toggle_emergency(s)
    toggle_emergency(s)
    assert (c.auto_block, c.total_block, c.panic, c.session_lock) == (
        True,
        False,
        False,
        False,
    )


def test_r1_shield_cuts_300pps_after_emergency_resume(tmp_path):
    from gui.profiles import toggle_emergency

    s = make_session(tmp_path)
    assert s.ctrl.auto_block
    toggle_emergency(s)
    toggle_emergency(s)
    assert s.ctrl.auto_block and not s.ctrl.filtering_paused
    flood = "198.51.100.17"
    feed(s, peers=[(flood, 300, 40)], seconds=8.0)
    assert flood in s.ctrl.blocked


def test_r2_letter_hotkeys_use_shift_not_altgr():
    from util.hotkeys import MOD_ALT, MOD_CONTROL, MOD_SHIFT

    by = {h.action: h for h in DEFAULT_HOTKEYS}
    assert by["emergency"].text == "Ctrl+Alt+F12"
    assert not by["emergency"].mods & MOD_SHIFT
    for a, letter in (("panic", "X"), ("auto", "A"), ("total", "T"), ("lock", "V")):
        assert by[a].mods == MOD_CONTROL | MOD_ALT | MOD_SHIFT
        assert by[a].text == f"Ctrl+Alt+Maj+{letter}"


def test_r3_commit_data_request_cleanup(monkeypatch):
    from gui import app

    calls = []
    monkeypatch.setattr(ls, "stop_background", lambda: calls.append("session"))
    wd = FakeWD()
    d = DriverLifecycle(wd)
    d.start()
    app.session_end_cleanup(d.cleanup)
    app.session_end_cleanup(d.cleanup)  # idempotent
    assert calls == ["session", "session"]
    assert wd.calls == ["register", "unregister"]
    app.session_end_cleanup(lambda: (_ for _ in ()).throw(RuntimeError("x")))


def test_r4_spoof_note_on_friends_page(gui):
    w, _s, _api = gui
    assert "usurpe" in w.friends.spoof_note.text()
    assert "Ctrl+Alt+Maj+X" in w.settings.hotkeys_text.text()
