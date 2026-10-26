"""Rapports d'incident : contenu, rapport allégé, rotation, robustesse, déclenchement."""

import json

import pytest
from guardian.menu import livesession as ls
from guardian.network import incident
from guardian.network.anomaly import Level, PeerState, SessionMonitor


def red_peer():
    mon = SessionMonitor()
    for k in range(61 * 30):
        mon.add_packet("90.84.1.1", 100, k / 30, port=6672)
        mon.add_packet("8.8.8.8", 100, k / 30, port=6672)
    for k in range(2700):
        mon.add_packet("90.84.1.1", 120, 61 + k / 900, port=61456)
    for k in range(90):
        mon.add_packet("8.8.8.8", 100, 61 + k / 30, port=6672)
    mon.evaluate(64)
    return mon.peers["90.84.1.1"]


def test_full_report_content(tmp_path):
    peer = red_peer()
    assert peer.level == Level.SUSPECT
    r = incident.build_report(peer, peer.ip, "auto", 64.0)
    assert not r["light"]
    assert r["source"] == {
        "ip": "90.84.1.1",
        "ports": [6672, 61456],
        "country": "FR",
        "asn": None,
        "direction": "inbound",
    }
    ev = r["evidence"]
    assert ev["anomaly"] == "burst" and ev["level"] == "suspect"
    assert ev["baseline_pps"] == 30 and ev["peak_pps"] >= 800
    assert ev["total_packets"] == 61 * 30 + 2700 and ev["max_size"] == 120
    assert 0 < len(ev["window_excerpt"]) <= incident.WINDOW_EXCERPT
    assert r["pseudo"] == "" and r["start"][-6] in "+-"  # fuseau présent
    paths = incident.write_report(r, tmp_path)
    assert paths is not None
    txt, js = paths
    assert json.loads(js.read_text(encoding="utf-8"))["id"] == r["id"]
    text = txt.read_text(encoding="utf-8")
    assert "Signalement" in text and "n'identifie pas un compte" in text
    assert "rafale" in text and "90.84.1.1" in text
    assert txt.name.endswith("_90.84.1.1.txt")


def test_light_report_manual_without_anomaly(tmp_path):
    peer = PeerState("8.8.8.8", 0.0, 10.0, total_packets=5, total_bytes=500)
    r = incident.build_report(peer, "8.8.8.8", "manual", 10.0, pseudo=" Bob ")
    assert r["light"] and r["pseudo"] == "Bob"
    assert "anomaly" not in r["evidence"]
    assert "rapport allégé" in incident.format_text(r)
    # IP inconnue de la vue (aucune stat) : rapport minimal quand même.
    r2 = incident.build_report(None, "192.168.1.2", "manual", 10.0)
    assert r2["light"] and r2["source"]["country"] is None
    assert incident.write_report(r2, tmp_path) is not None


def test_rotation_keeps_last(tmp_path):
    for i in range(12):
        r = incident.build_report(None, f"1.1.1.{i}", "manual", 1_700_000_000.0 + i)
        incident.write_report(r, tmp_path)
    incident.rotate(tmp_path, keep=5)
    assert len(list(tmp_path.glob("*.json"))) == 5
    assert len(list(tmp_path.glob("*.txt"))) == 5
    assert not list(tmp_path.glob("*.tmp"))


def test_same_second_same_ip_no_overwrite(tmp_path):
    r = incident.build_report(None, "1.1.1.1", "manual", 1_700_000_000.0)
    a = incident.write_report(r, tmp_path)
    b = incident.write_report(r, tmp_path)
    assert a and b and a[0] != b[0]


def test_write_never_raises(tmp_path, monkeypatch):
    r = incident.build_report(None, "1.1.1.1", "manual", 1.0)
    blocker = tmp_path / "fichier"
    blocker.write_text("x")
    assert (
        incident.write_report(r, blocker / "sous-dossier") is None
    )  # mkdir impossible

    def full(*_a, **_k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("pathlib.Path.write_text", full)
    assert incident.write_report(r, tmp_path) is None


def test_report_writer_thread(tmp_path):
    w = incident.ReportWriter(tmp_path)
    w.submit(incident.build_report(None, "1.1.1.1", "manual", 1.0))
    w.close()
    assert len(w.written) == 1 and w.written[0].exists()


def test_english_report():
    from guardian.util import i18n

    import util.i18n as live_i18n  # même module que celui utilisé par incident.py

    try:
        live_i18n.set_language("en", persist=False)
        text = incident.format_text(
            incident.build_report(None, "1.1.1.1", "manual", 1.0)
        )
        assert "does not identify an account" in text
    finally:
        live_i18n.set_language("fr", persist=False)
        i18n.set_language("fr", persist=False)


# -- déclenchement depuis la vue en direct ----------------------------------------


class FakeList(dict):
    def __iter__(self):
        return iter(self.items())

    def add(self, ip, name):
        self[ip] = name

    def save(self):
        pass


def test_report_on_manual_and_auto_block():
    calls = []
    ctrl = ls.LiveSessionController(
        {}, FakeList(), auto_block=True, reporter=lambda *a: calls.append(a)
    )
    ctrl.block("1.1.1.1", "Bob")
    ctrl.auto_block_if_needed(PeerState("2.2.2.2", 0, 0, level=Level.SUSPECT))
    assert calls == [("1.1.1.1", "manual", "Bob"), ("2.2.2.2", "auto", "")]


def test_reporter_failure_does_not_prevent_block():
    def boom(*_a):
        raise RuntimeError

    blocked = {}
    ctrl = ls.LiveSessionController(blocked, FakeList(), reporter=boom)
    ctrl.block("1.1.1.1")
    assert "1.1.1.1" in blocked


@pytest.mark.parametrize("requested", [True, False])
def test_auto_shield_disabled_without_ranges(requested):
    blocked = {}
    ctrl = ls.LiveSessionController(
        blocked, FakeList(), auto_block=requested, auto_block_available=False
    )
    assert not ctrl.auto_block
    ctrl.toggle_auto_block()
    assert not ctrl.auto_block
    assert not ctrl.auto_block_if_needed(
        PeerState("2.2.2.2", 0, 0, level=Level.SUSPECT)
    )
    assert not blocked
    out = ls.render(SessionMonitor(), ctrl, [], "off", 0.0)
    assert "plages Rockstar/Azure indisponibles" in out


def test_guard_reported_is_bounded(monkeypatch):
    monkeypatch.setattr(ls, "GUARD_REPORTED_MAX", 10)
    ctrl = ls.LiveSessionController(
        {}, FakeList(), auto_block=True, auto_block_guard=lambda _ip: True
    )
    for i in range(50):
        ctrl.auto_block_if_needed(PeerState(f"1.1.1.{i}", 0, 0, level=Level.SUSPECT))
    assert len(ctrl._guard_reported) <= 10
