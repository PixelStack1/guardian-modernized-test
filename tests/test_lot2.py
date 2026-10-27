"""Lot 2 : verrou de session, récidivistes, liste d'amis, bouton panique, rejeu."""

import json
from pathlib import Path

import pytest
from guardian import replay as rp
from guardian.menu import livesession as ls
from guardian.network.anomaly import Level, PeerState
from guardian.network.offenders import OffenderStore
from hypothesis import given
from hypothesis import strategies as st

ROCKSTAR = "185.56.65.10"  # plage officielle Take-Two (T2_EU_FALLBACK)
FIXTURE = Path(__file__).parent / "fixtures" / "session_lot2.csv"


class FakeList(dict):
    def __iter__(self):
        return iter(self.items())

    def add(self, ip, name):
        self[ip] = name

    def remove(self, ip):
        self.pop(ip)

    def save(self):
        pass


class FakeConfig:
    def __init__(self):
        self.data = {}
        self.saves = 0

    def save(self):
        self.saves += 1


def make(tmp_path, **kw):
    clock = [1000.0]
    beeps = []
    store = OffenderStore(tmp_path / "rec.json", guard=ls.is_rockstar_server)
    ctrl = ls.LiveSessionController(
        {},
        FakeList(),
        clock=lambda: clock[0],
        offenders=store,
        sound=lambda: beeps.append(1),
        **kw,
    )
    return ctrl, store, beeps, clock


def suspect(ip):
    p = PeerState(ip, first_seen=0.0, last_seen=0.0)
    p.level = Level.SUSPECT
    p.reason_key = "reason.burst"
    return p


# -- LivePolicy (décision par paquet) ----------------------------------------


def test_defaults_off():
    assert ls.SESSION_LOCK_DEFAULT is False
    assert ls.OFFENDER_SOUND_DEFAULT is True
    assert ls.OFFENDER_DROP_DEFAULT is True
    pol = ls.LivePolicy()
    assert not pol.drop(True, "192.0.2.1")


def test_lock_drops_only_unseen_inbound():
    pol = ls.LivePolicy()
    assert not pol.drop(True, "192.0.2.1")  # vu avant le verrou
    pol.lock_on = True
    assert not pol.drop(True, "192.0.2.1")
    assert pol.drop(True, "203.0.113.9")
    assert pol.drop(True, "203.0.113.9")  # jamais mémorisé pendant le verrou
    assert not pol.drop(False, "203.0.113.9")  # sortant jamais concerné
    assert not pol.drop(True, ROCKSTAR)


def test_lock_seen_is_bounded():
    pol = ls.LivePolicy(max_seen=2)
    for ip in ("192.0.2.1", "192.0.2.2", "192.0.2.3"):
        pol.drop(True, ip)
    assert pol.seen == {"192.0.2.1", "192.0.2.2"}


def test_offender_cut_and_friend_and_panic():
    pol = ls.LivePolicy(offenders={"198.51.100.7", ROCKSTAR}, offender_drop=True)
    assert pol.drop(True, "198.51.100.7")
    assert not pol.drop(True, ROCKSTAR)
    pol.offender_drop = False
    assert not pol.drop(True, "198.51.100.7")
    pol.friends = {"198.51.100.7"}
    pol.offender_drop = True
    assert not pol.drop(True, "198.51.100.7")
    pol.panic = True
    assert pol.drop(True, "192.0.2.50")
    assert not pol.drop(True, "198.51.100.7")  # ami
    assert not pol.drop(True, ROCKSTAR)
    assert not pol.drop(False, "192.0.2.50")


def test_bypass_hook_and_fail_safe():
    pol = ls.LivePolicy(lock_on=True, bypass=lambda ip: ip == "192.0.2.9")
    assert not pol.drop(True, "192.0.2.9")

    def boom(_ip):
        raise RuntimeError

    assert not ls.LivePolicy(lock_on=True, bypass=boom).drop(True, "192.0.2.8")


@given(st.ip_addresses(v=4).map(str), st.booleans(), st.booleans(), st.booleans())
def test_never_drops_rockstar_or_friend(ip, lock, panic, cut):
    pol = ls.LivePolicy(
        lock_on=lock, panic=panic, offender_drop=cut, offenders={ip}, friends={ip}
    )
    assert not pol.drop(True, ip)
    pol2 = ls.LivePolicy(
        lock_on=lock, panic=panic, offender_drop=cut, offenders={ROCKSTAR}
    )
    assert not pol2.drop(True, ROCKSTAR)


def test_handle_packet_only_sends_original(packet_factory):
    sent = []

    class W:
        def send(self, p):
            sent.append(p)

    pol = ls.LivePolicy(lock_on=True)
    pkt = packet_factory(src="203.0.113.10")
    assert not ls.handle_packet(W(), pkt, {}, {}, 0.0, policy=pol)
    assert sent == []
    pol.lock_on = False
    assert ls.handle_packet(W(), pkt, {}, {}, 0.0, policy=pol)
    assert sent == [pkt]
    out = packet_factory(src="192.168.1.2", dst="203.0.113.99", inbound=False)
    pol.panic = True
    assert ls.handle_packet(W(), out, {}, {}, 0.0, policy=pol)
    assert sent[-1] is out


# -- Récidivistes ------------------------------------------------------------


def test_store_metadata_only_bounded_and_rockstar_excluded(tmp_path):
    path = tmp_path / "rec.json"
    store = OffenderStore(path, guard=ls.is_rockstar_server, limit=2)
    assert not store.record(ROCKSTAR, "manual", 1.0)
    assert not store.record("not-an-ip", "manual", 1.0)
    store.record("192.0.2.1", "manual", 1.0)
    store.record("192.0.2.1", "reason.burst", 5.0)
    store.record("192.0.2.2", "manual", 2.0)
    store.record("192.0.2.3", "manual", 3.0)
    data = json.loads(path.read_text())
    assert set(data) == {"192.0.2.1", "192.0.2.3"}
    assert data["192.0.2.1"] == {
        "first": 1.0,
        "last": 5.0,
        "count": 2,
        "reason": "reason.burst",
    }
    assert set(OffenderStore(path, limit=2).ips()) == {"192.0.2.1", "192.0.2.3"}


def test_store_corrupt_file_is_empty(tmp_path):
    path = tmp_path / "rec.json"
    path.write_text("{oops")
    assert len(OffenderStore(path)) == 0
    path.write_text(json.dumps({"192.0.2.1": {"first": 1, "last": 1, "count": "x"}}))
    assert len(OffenderStore(path)) == 0


def test_manual_and_auto_block_record_and_unblock_removes(tmp_path):
    ctrl, store, beeps, _ = make(tmp_path, auto_block=True)
    ctrl.block("192.0.2.5")
    assert store.get("192.0.2.5").reason == "manual"
    assert ctrl.auto_block_if_needed(suspect("192.0.2.6"))
    assert "192.0.2.6" in store and "192.0.2.6" in ctrl.offender_ips
    ctrl.block(ROCKSTAR)
    assert ROCKSTAR not in store
    ctrl.unblock("192.0.2.5")
    assert "192.0.2.5" not in store and "192.0.2.5" not in ctrl.offender_ips
    assert beeps == []  # pas d'alerte au moment du blocage


def test_offender_reappears_alert_once_with_sound(tmp_path):
    store = OffenderStore(tmp_path / "rec.json")
    store.record("198.51.100.7", "manual", 1.0)
    ctrl, _, beeps, _ = make(tmp_path)
    assert "198.51.100.7" in ctrl.offender_ips
    assert ctrl.offender_check("198.51.100.7", False) is None
    line = ctrl.offender_check("198.51.100.7", True)
    assert line and "198.51.100.7" in line and line in ctrl.events
    assert beeps == [1]
    assert ctrl.offender_check("198.51.100.7", True) is None
    assert beeps == [1]


def test_sound_setting_off(tmp_path):
    OffenderStore(tmp_path / "rec.json").record("198.51.100.7", "manual", 1.0)
    ctrl, _, beeps, _ = make(tmp_path, offender_sound=False)
    assert ctrl.offender_check("198.51.100.7", True)
    assert beeps == []


def test_beep_is_noop_off_windows(monkeypatch):
    from guardian.util import sound

    monkeypatch.setattr(sound.sys, "platform", "linux")
    assert sound.beep() is False


# -- Amis et panique ---------------------------------------------------------


def test_friend_add_remove_label_and_protections(tmp_path):
    ctrl, store, _, _ = make(tmp_path, auto_block=True)
    ctrl.block("192.0.2.7")
    assert ctrl.add_friend("192.0.2.7", "  Bob  le   pote ")
    assert ctrl.friends["192.0.2.7"] == "Bob le pote"
    assert "192.0.2.7" not in ctrl.blocked and "192.0.2.7" not in store
    assert ctrl.label("192.0.2.7") == "Bob le pote"
    assert ctrl.label("192.0.2.8") == "192.0.2.8"
    assert not ctrl.auto_block_if_needed(suspect("192.0.2.7"))
    assert not ctrl.add_friend(ROCKSTAR, "x")
    assert ctrl.remove_friend("192.0.2.7")
    assert not ctrl.remove_friend("192.0.2.7")


def test_friend_is_never_offender_alerted(tmp_path):
    OffenderStore(tmp_path / "rec.json").record("198.51.100.7", "manual", 1.0)
    ctrl, _, beeps, _ = make(tmp_path, friends={"198.51.100.7": "Al"})
    assert ctrl.offender_check("198.51.100.7", True) is None and beeps == []


def test_load_friends_validates():
    raw = {"192.0.2.1": "A", "bad": "B", ROCKSTAR: "C", "192.0.2.2": 3}
    assert ls.load_friends(raw) == {"192.0.2.1": "A"}
    assert ls.load_friends(["x"]) == {}


def test_keys_toggle_and_persist(tmp_path):
    ctrl, _, _, _ = make(tmp_path)
    cfg = FakeConfig()

    class Flag:
        value = 0

    ctrl.lock_flag = lock = Flag()
    ctrl.panic_flag = panic = Flag()
    peers = [PeerState("192.0.2.30", first_seen=0.0, last_seen=0.0)]
    answers = iter(["1", "Zoé", "1"])
    prompt = lambda _t: next(answers)  # noqa: E731
    ls.handle_key("v", ctrl, peers, ctrl.blocked, None, prompt, cfg)
    assert ctrl.session_lock and cfg.data[ls.SESSION_LOCK_KEY] is True and lock.value
    ls.handle_key("s", ctrl, peers, ctrl.blocked, None, prompt, cfg)
    assert cfg.data[ls.OFFENDER_SOUND_KEY] is False
    ls.handle_key("c", ctrl, peers, ctrl.blocked, None, prompt, cfg)
    assert cfg.data[ls.OFFENDER_DROP_KEY] is False
    ls.handle_key("x", ctrl, peers, ctrl.blocked, None, prompt, cfg)
    assert ctrl.panic and panic.value
    ls.handle_key("f", ctrl, peers, ctrl.blocked, None, prompt, cfg)
    assert cfg.data[ls.FRIENDS_KEY] == {"192.0.2.30": "Zoé"}
    ls.handle_key("f", ctrl, peers, ctrl.blocked, None, prompt, cfg)
    assert cfg.data[ls.FRIENDS_KEY] == {}
    ls.handle_key("x", ctrl, peers, ctrl.blocked, None, prompt, cfg)
    assert not ctrl.panic


def test_head_shows_lot2_status(tmp_path):
    ctrl, _, _, _ = make(tmp_path, friends={"192.0.2.1": "Ami"})
    head = "\n".join(ls.render_head(ctrl, ""))
    assert "V" in head and "X" in head and "S)" in head
    assert len(ls.t("live.keys")) < 100


# -- Rejeu -------------------------------------------------------------------


def run(**kw):
    lines = []
    with FIXTURE.open(newline="", encoding="utf-8") as f:
        res = rp.replay(rp.read_rows(f), emit=lines.append, **kw)
    return res, lines


def test_fixture_documentation_ranges_only():
    ips = {row[1] for row in rp.read_rows(FIXTURE.open(encoding="utf-8"))}
    assert ips and all(
        ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")) for ip in ips
    )


def test_replay_default_drops_nothing():
    res, _ = run()
    assert res.dropped == 0


def test_replay_lock():
    res, lines = run(lock_after=1.0)
    assert set(res.dropped_lock) == {"203.0.113.50", "203.0.113.80"}
    assert res.dropped_lock["203.0.113.50"] == 2
    assert any("203.0.113.50" in ln for ln in lines)


def test_replay_offender_cut_and_alert_only():
    res, _ = run(offenders=["198.51.100.7"])
    assert res.offender_alerts == ["198.51.100.7"]
    assert res.dropped_offender["198.51.100.7"] == 2
    res, _ = run(offenders=["198.51.100.7"], offender_drop=False)
    assert res.offender_alerts == ["198.51.100.7"] and res.dropped == 0


def test_replay_friend_bypasses_lock_and_panic():
    res, _ = run(lock_after=1.0, friends={"203.0.113.80": "Ami"})
    assert "203.0.113.80" not in res.dropped_by_ip
    res, _ = run(panic_after=3.0, friends={"192.0.2.10": "Ami"})
    assert set(res.dropped_panic) == {"192.0.2.20"}


def test_replay_cli_flags(capsys):
    code = rp.main(
        [
            str(FIXTURE),
            "--verrou",
            "1",
            "--recidiviste",
            "198.51.100.7",
            "--ami",
            "203.0.113.80=Ami",
            "--panique",
            "3",
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "203.0.113.50" in out and "198.51.100.7" in out
    assert "203.0.113.80 serait" not in out  # ami : jamais jeté


@pytest.mark.parametrize("flag", ["--verrou", "--panique"])
def test_replay_cli_rejects_bad_number(flag):
    with pytest.raises(SystemExit):
        rp.main([str(FIXTURE), flag, "abc"])
