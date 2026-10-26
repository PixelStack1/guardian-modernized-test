"""Blocage manuel / automatique de la vue Session en direct (sans WinDivert)."""

from guardian.menu import livesession as ls
from guardian.network.anomaly import Level, PeerState


class FakeList(dict):
    saved = 0

    def __iter__(self):
        return iter(self.items())

    def add(self, ip, name):
        self[ip] = name

    def remove(self, ip):
        self.pop(ip)

    def save(self):
        self.saved += 1


def make(auto=False, existing=None):
    clock = [1000.0]
    bl = FakeList(existing or {})
    blocked = {}
    ctrl = ls.LiveSessionController(blocked, bl, auto, clock=lambda: clock[0])
    return ctrl, blocked, bl, clock


def test_existing_blacklist_is_blocked():
    _, blocked, _, _ = make(existing={"9.9.9.9": "x"})
    assert ls.is_blocked(blocked, "9.9.9.9", 0)


def test_manual_block_persists_with_pseudo_and_date():
    ctrl, blocked, bl, _ = make()
    ctrl.pseudos["1.1.1.1"] = "Tryhard42"
    ctrl.block("1.1.1.1")
    assert ls.is_blocked(blocked, "1.1.1.1", 10**12)
    assert bl["1.1.1.1"].startswith("Tryhard42 [bloqué le ")
    assert bl.saved == 1
    ctrl.unblock("1.1.1.1")
    assert "1.1.1.1" not in bl and "1.1.1.1" not in blocked


def test_auto_block_off_by_default():
    ctrl, blocked, _, _ = make()
    p = PeerState("1.1.1.1", 0, 0, level=Level.SUSPECT)
    assert not ctrl.auto_block_if_needed(p)
    assert not blocked


def test_auto_block_temporary_not_persisted():
    ctrl, blocked, bl, clock = make(auto=True)
    orange = PeerState("2.2.2.2", 0, 0, level=Level.INHABITUEL)
    red = PeerState("1.1.1.1", 0, 0, level=Level.SUSPECT)
    assert not ctrl.auto_block_if_needed(orange)
    assert ctrl.auto_block_if_needed(red)
    assert ls.is_blocked(blocked, "1.1.1.1", clock[0])
    assert "1.1.1.1" not in bl
    clock[0] += ls.AUTO_BLOCK_SECONDS
    ctrl.expire()
    assert "1.1.1.1" not in blocked


def test_blacklist_label():
    from datetime import datetime

    d = datetime(2026, 10, 26, 7, 0, 0)
    assert ls.blacklist_label("", d) == "Bloqué le 2026-10-26 07:00:00"
    assert ls.blacklist_label(" Bob ", d) == "Bob [bloqué le 2026-10-26 07:00:00]"
