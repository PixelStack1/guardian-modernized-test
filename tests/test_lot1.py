"""Lot 1 : réglage relais Rockstar, alerte/journal nouveau joueur, mode rejeu."""

import io
from pathlib import Path

import pytest

import replay as rp
from menu import livesession as ls
from network import relay
from network.newplayer import (
    JOURNAL_NAME,
    NewPlayerTracker,
    PlayerJournal,
    format_line,
)

FIXTURE = Path(__file__).parent / "fixtures" / "session_anonymisee.csv"
ROCKSTAR = "185.56.65.10"  # plage officielle Take-Two (T2_EU_FALLBACK)
PLAYER = "203.0.113.5"
DOC_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")


class FakeBL:
    def __iter__(self):
        return iter([])

    def __contains__(self, ip):
        return False

    def add(self, ip, name):
        pass

    def remove(self, ip):
        pass

    def save(self):
        pass


class Flag:
    value = 0


class Cfg:
    def __init__(self):
        self.data = {}
        self.saved = 0

    def save(self):
        self.saved += 1


# -- relais Rockstar ---------------------------------------------------------
def test_relay_default_is_allow_and_normalize_failsafe():
    assert relay.RELAY_DEFAULT == "autoriser"
    assert relay.load_mode({}) == "autoriser"
    assert relay.load_mode({"rockstar_relay": "BLOQUER "}) == "bloquer"
    for bad in (None, 1, "", "oui", ["bloquer"]):
        assert relay.normalize(bad) == "autoriser"
    assert relay.toggled("autoriser") == "bloquer"
    assert relay.toggled("bloquer") == "autoriser"


def test_should_drop_default_never_drops_rockstar():
    assert ls.is_rockstar_server(ROCKSTAR)
    for inbound in (True, False):
        assert not ls.should_drop(inbound, ROCKSTAR, ROCKSTAR, {}, {}, 0.0)
        assert not ls.should_drop(inbound, ROCKSTAR, ROCKSTAR, {}, {}, 0.0, True, False)


def test_should_drop_relay_block_drops_both_directions_only_rockstar():
    assert ls.should_drop(True, ROCKSTAR, "192.168.1.2", {}, {}, 0.0, False, True)
    assert ls.should_drop(False, "192.168.1.2", ROCKSTAR, {}, {}, 0.0, False, True)
    assert not ls.should_drop(True, PLAYER, "192.168.1.2", {}, {}, 0.0, False, True)
    assert not ls.should_drop(False, "192.168.1.2", PLAYER, {}, {}, 0.0, False, True)


def test_handle_packet_relay_block_only_drops_or_sends_original(packet_factory):
    class W:
        def __init__(self):
            self.sent = []

        def send(self, p):
            self.sent.append(p)

    w = W()
    pkt = packet_factory(src=ROCKSTAR)
    assert ls.handle_packet(w, pkt, {}, {}, 0.0) is True  # défaut : passe
    assert w.sent == [pkt] and w.sent[0] is pkt
    assert ls.handle_packet(w, pkt, {}, {}, 0.0, False, True) is False
    assert len(w.sent) == 1  # rien d'envoyé, rien de fabriqué
    other = packet_factory(src=PLAYER)
    assert ls.handle_packet(w, other, {}, {}, 0.0, False, True) is True
    assert w.sent[-1] is other


def test_controller_relay_flag_toggle_and_persist():
    flag = Flag()
    ctrl = ls.LiveSessionController({}, FakeBL(), relay_flag=flag)
    assert ctrl.relay_mode == "autoriser" and not ctrl.relay_block
    assert flag.value is False
    cfg = Cfg()
    ls.handle_key("l", ctrl, [], {}, None, lambda _p: "", cfg)
    assert ctrl.relay_mode == "bloquer" and flag.value is True
    assert cfg.data["rockstar_relay"] == "bloquer" and cfg.saved == 1
    ls.handle_key("l", ctrl, [], {}, None, lambda _p: "", cfg)
    assert cfg.data["rockstar_relay"] == "autoriser" and flag.value is False


def test_controller_relay_invalid_mode_is_allow():
    ctrl = ls.LiveSessionController({}, FakeBL(), relay_mode="n'importe quoi")
    assert ctrl.relay_mode == "autoriser"


@pytest.mark.parametrize("lang", ["fr", "en"])
def test_relay_strings_fr_en_and_head(lang):
    from util import i18n

    i18n.set_language(lang, persist=False)
    try:
        for key in (
            "live.relay_status",
            "live.relay_allow",
            "live.relay_block",
            "live.ev.relay_toggled",
            "live.ev.new_player",
            "replay.drop",
            "replay.summary",
        ):
            assert set(i18n.STRINGS[key]) == {"fr", "en"}
        ctrl = ls.LiveSessionController({}, FakeBL())
        head = "\n".join(ls.render_head(ctrl, "rec"))
        assert i18n.t("live.relay_allow") in head
        assert len(i18n.t("live.keys")) <= 100
    finally:
        i18n.set_language("fr", persist=False)


# -- nouveau joueur + journal ------------------------------------------------
def test_tracker_alerts_once_inbound_only_and_skips_rockstar(tmp_path):
    journal = PlayerJournal(tmp_path)
    tr = NewPlayerTracker(ls.is_rockstar_server, journal)
    assert tr.observe(1.0, PLAYER, inbound=False) is None  # sortant : jamais
    assert tr.observe(1.0, ROCKSTAR, inbound=True) is None
    assert tr.observe(2.0, PLAYER, inbound=True)
    assert tr.observe(3.0, PLAYER, inbound=True) is None
    lines = (tmp_path / JOURNAL_NAME).read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1 and PLAYER in lines[0] and ROCKSTAR not in lines[0]


def test_journal_line_format_metadata_only():
    line = format_line(0.0, PLAYER, "FR")
    assert line.split("  ")[1:] == [PLAYER, "FR"]
    assert "ms" not in line  # ping inconnu : omis
    assert format_line(0.0, PLAYER, None, 42.4).endswith("—  42 ms")


def test_journal_rotation_is_bounded(tmp_path):
    j = PlayerJournal(tmp_path, max_bytes=200, backups=2)
    for i in range(100):
        j.write(format_line(float(i), f"192.0.2.{i}", None))
    files = sorted(p.name for p in tmp_path.iterdir())
    assert files == [JOURNAL_NAME, JOURNAL_NAME + ".1", JOURNAL_NAME + ".2"]
    assert all((tmp_path / f).stat().st_size <= 200 for f in files)


def test_journal_never_raises(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    PlayerJournal(blocker).write("ligne")  # dossier impossible : silencieux


def test_tracker_memory_bounded():
    tr = NewPlayerTracker(lambda _ip: False, None, max_tracked=3)
    for i in range(10):
        tr.observe(0.0, f"192.0.2.{i}", True)
    assert len(tr.seen) == 3


def test_default_journal_under_localappdata(monkeypatch, tmp_path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert PlayerJournal().path == tmp_path / "Guardian" / "journal" / JOURNAL_NAME


def test_background_step_emits_new_player_event(tmp_path):
    import queue as q

    ctrl = ls.LiveSessionController({}, FakeBL())
    packets: q.Queue = q.Queue()
    packets.put((1.0, PLAYER, 100, True, 6672))
    packets.put((1.1, ROCKSTAR, 100, True, 6672))

    class Rec:
        active = False

        def write(self, *a):
            pass

    from network.anomaly import SessionMonitor

    tracker = NewPlayerTracker(ls.is_rockstar_server, PlayerJournal(tmp_path))
    s = ls.BackgroundSession(
        None,
        packets,
        ctrl,
        SessionMonitor(),
        ls.PlayerCounter(),
        Rec(),
        new_players=tracker,
    )
    s.step(0.01)
    s.step(0.01)
    assert len(ctrl.events) == 1 and PLAYER in ctrl.events[0]


# -- mode rejeu --------------------------------------------------------------
def test_fixture_uses_documentation_ranges_only():
    rows = list(rp.read_rows(FIXTURE.open(encoding="utf-8")))
    assert rows
    assert all(ip.startswith(DOC_NETS) for _ts, ip, _s, _i in rows)


def test_read_rows_requires_header_and_skips_bad_lines():
    with pytest.raises(ValueError):
        list(rp.read_rows(io.StringIO("a,b,c,d\n")))
    text = (
        "horodatage,ip,taille,sens\n1.0,192.0.2.1,10,entrant\nbad\n"
        "x,192.0.2.1,1,entrant\n2.0,192.0.2.1,1,???\n3.0,192.0.2.2,5,sortant\n"
    )
    assert list(rp.read_rows(io.StringIO(text))) == [
        (1.0, "192.0.2.1", 10, True),
        (3.0, "192.0.2.2", 5, False),
    ]


def test_replay_fixture_default_alerts_and_drops_nothing():
    out: list[str] = []
    rows = rp.read_rows(FIXTURE.open(encoding="utf-8"))
    res = rp.replay(rows, emit=out.append)
    assert sorted(res.new_players) == [
        "192.0.2.10",
        "198.51.100.20",
        "203.0.113.30",
        "203.0.113.66",
    ]
    assert res.dropped == 0 and not res.servers


def test_replay_fixture_auto_shield_drops_burst_peer():
    rows = rp.read_rows(FIXTURE.open(encoding="utf-8"))
    res = rp.replay(rows, auto_block=True, emit=lambda _l: None)
    assert set(res.dropped_by_ip) == {"203.0.113.66"}
    assert res.dropped > 0


def test_replay_relay_setting():
    rows = [
        (1.0, ROCKSTAR, 100, True),
        (1.1, ROCKSTAR, 80, False),
        (1.2, PLAYER, 100, True),
    ]
    allow = rp.replay(rows, emit=lambda _l: None)
    assert allow.dropped == 0 and allow.servers == {ROCKSTAR}
    assert allow.new_players == [PLAYER]  # serveur jamais compté comme joueur
    block = rp.replay(rows, relay_mode="bloquer", emit=lambda _l: None)
    assert block.dropped_by_ip == {ROCKSTAR: 2}


def test_replay_cli(capsys, tmp_path):
    assert rp.main([str(FIXTURE), "--lang", "en", "--journal", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "New player: 192.0.2.10" in out and "Replay:" in out
    assert (tmp_path / JOURNAL_NAME).read_text(encoding="utf-8").count("\n") == 4
    assert rp.main([str(tmp_path / "absent.csv")]) == 2
    from util import i18n

    i18n.set_language("fr", persist=False)
