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


def make(auto=None, existing=None):
    clock = [1000.0]
    bl = FakeList(existing or {})
    blocked = {}
    kwargs = {} if auto is None else {"auto_block": auto}
    ctrl = ls.LiveSessionController(blocked, bl, clock=lambda: clock[0], **kwargs)
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


def test_auto_block_on_by_default_red_only():
    ctrl, blocked, bl, _ = make()
    assert ctrl.auto_block
    p = PeerState("1.1.1.1", 0, 0, level=Level.SUSPECT, reason_key="reason.burst")
    assert ctrl.auto_block_if_needed(p)
    assert "1.1.1.1" in blocked and "1.1.1.1" not in bl
    assert ctrl.events[-1].startswith("Bouclier auto : 1.1.1.1 bloqué (rafale)")
    orange = PeerState("2.2.2.2", 0, 0, level=Level.INHABITUEL)
    assert not ctrl.auto_block_if_needed(orange)
    assert "2.2.2.2" not in blocked


def test_auto_block_can_be_disabled():
    ctrl, blocked, _, _ = make(auto=False)
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
