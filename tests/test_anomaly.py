"""Fenêtre glissante, apprentissage de la normale et détection d'anomalies."""

import csv

from guardian.network import anomaly as an
from guardian.network.anomaly import Level, SessionMonitor, SlidingWindow
from hypothesis import given, settings
from hypothesis import strategies as st


def feed(mon, ip, pps, start, end, size=100):
    """Envoie ``pps`` paquets/s réguliers de ``ip`` entre start et end."""
    n = int((end - start) * pps)
    for i in range(n):
        mon.add_packet(ip, size, start + i / pps)


def learned(mon, ips, pps=30):
    for ip in ips:
        feed(mon, ip, pps, 0, an.BASELINE_SECONDS + 1)
    return an.BASELINE_SECONDS + 1


# -- fenêtre glissante ------------------------------------------------------


def test_window_stats_basic():
    w = SlidingWindow(2.0)
    for i in range(10):
        w.add(i * 0.1, 50 + i)
    s = w.stats(1.0)
    assert s.pps == 5.0
    assert s.max_size == 59
    assert s.avg_size == sum(range(50, 60)) / 10
    assert s.bps == sum(range(50, 60)) / 2


def test_window_expires():
    w = SlidingWindow(1.0)
    w.add(0.0, 10)
    assert w.stats(0.5).pps == 1.0
    assert w.stats(1.0).pps == 0.0
    assert w.stats(1.0).max_size == 0


@settings(max_examples=300)
@given(
    st.lists(
        st.tuples(st.floats(0, 1000, allow_nan=False), st.integers(0, 65535)),
        max_size=200,
    ),
    st.floats(0.1, 30, allow_nan=False),
)
def test_window_matches_bruteforce(items, seconds):
    items.sort()
    w = SlidingWindow(seconds)
    for ts, size in items:
        w.add(ts, size)
    now = items[-1][0] if items else 0.0
    alive = [s for ts, s in items if ts > now - seconds]
    st_ = w.stats(now)
    assert st_.pps == len(alive) / seconds
    assert st_.max_size == (max(alive) if alive else 0)
    assert abs(st_.bps - sum(alive) / seconds) < 1e-6


@settings(max_examples=200)
@given(
    st.lists(
        st.tuples(
            st.sampled_from(["1.1.1.1", "2.2.2.2", "3.3.3.3"]),
            st.integers(-5, 70000),
            st.floats(0, 200, allow_nan=False),
        ),
        max_size=300,
    )
)
def test_monitor_never_crashes(events):
    mon = SessionMonitor()
    for ip, size, ts in sorted(events, key=lambda e: e[2]):
        mon.add_packet(ip, size, ts)
        mon.evaluate(ts)
    for p in mon.peers.values():
        assert p.level in Level


# -- détection -----------------------------------------------------------


def test_no_alert_during_learning_or_steady():
    mon = SessionMonitor()
    feed(mon, "1.1.1.1", 500, 0, 10)  # gros débit mais en apprentissage
    assert all(p.level == Level.NORMAL for p in mon.evaluate(10))
    mon = SessionMonitor()
    t = learned(mon, ["1.1.1.1", "2.2.2.2"])
    feed(mon, "1.1.1.1", 30, t, t + 20)
    feed(mon, "2.2.2.2", 30, t, t + 20)
    assert all(p.level == Level.NORMAL for p in mon.evaluate(t + 20))


def test_burst_targeted_orange_then_red():
    mon = SessionMonitor()
    t = learned(mon, ["1.1.1.1", "2.2.2.2", "3.3.3.3"])
    # 1.1.1.1 passe de 30 à 200 paquets/s (~6.7x) ; les autres restent normaux.
    feed(mon, "2.2.2.2", 30, t, t + 10)
    feed(mon, "3.3.3.3", 30, t, t + 10)
    feed(mon, "1.1.1.1", 200, t, t + 4)
    mon.evaluate(t + 4)
    p = mon.peers["1.1.1.1"]
    assert p.level == Level.INHABITUEL
    assert "rafale de 200 paquets/s, normale 30" in p.alert
    assert "ciblée" in p.alert
    feed(mon, "1.1.1.1", 200, t + 4, t + 10)
    mon.evaluate(t + 10)
    assert p.level == Level.SUSPECT
    assert mon.peers["2.2.2.2"].level == Level.NORMAL


def test_severe_burst_is_red_immediately():
    mon = SessionMonitor()
    t = learned(mon, ["1.1.1.1", "2.2.2.2"])
    feed(mon, "2.2.2.2", 30, t, t + 4)
    feed(mon, "1.1.1.1", 900, t + 1, t + 4)
    mon.evaluate(t + 4)
    assert mon.peers["1.1.1.1"].level == Level.SUSPECT


def test_session_wide_burst_is_not_flagged():
    mon = SessionMonitor()
    ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]
    t = learned(mon, ips)
    for ip in ips:
        feed(mon, ip, 300, t, t + 4)
    assert all(p.level == Level.NORMAL for p in mon.evaluate(t + 4))


def test_burst_baseline_floor():
    mon = SessionMonitor()
    t = learned(mon, ["1.1.1.1"], pps=1)
    feed(mon, "1.1.1.1", 40, t, t + 4)  # 40x mais < BURST_MIN_PPS
    mon.evaluate(t + 4)
    assert mon.peers["1.1.1.1"].level == Level.NORMAL


def test_baseline_robust_to_learning_spike():
    mon = SessionMonitor()
    feed(mon, "1.1.1.1", 30, 0, an.BASELINE_SECONDS + 1)
    feed(mon, "1.1.1.1", 2000, 5, 6)  # pic bref pendant l'apprentissage
    mon.evaluate(an.BASELINE_SECONDS + 1)
    assert mon.peers["1.1.1.1"].baseline_pps == 30


def test_huge_packets_flagged():
    mon = SessionMonitor()
    t = learned(mon, ["1.1.1.1", "2.2.2.2"])
    feed(mon, "2.2.2.2", 30, t, t + 4, size=400)
    feed(mon, "1.1.1.1", 30, t, t + 4, size=1400)
    mon.evaluate(t + 4)
    p = mon.peers["1.1.1.1"]
    assert p.level >= Level.INHABITUEL
    assert "paquets énormes" in p.alert


def test_tiny_identical_run_flagged_but_not_heartbeats():
    mon = SessionMonitor()
    t = learned(mon, ["1.1.1.1", "2.2.2.2"])
    feed(mon, "1.1.1.1", 60, t, t + 4, size=4)
    feed(mon, "2.2.2.2", 60, t, t + 4, size=12)  # taille de heartbeat ignorée
    mon.evaluate(t + 4)
    assert "petits paquets identiques" in mon.peers["1.1.1.1"].alert
    assert mon.peers["2.2.2.2"].level == Level.NORMAL


def test_returns_to_normal_after_calm():
    mon = SessionMonitor()
    t = learned(mon, ["1.1.1.1", "2.2.2.2"])
    feed(mon, "2.2.2.2", 30, t, t + 2)
    feed(mon, "1.1.1.1", 300, t, t + 2)
    mon.evaluate(t + 2)
    assert mon.peers["1.1.1.1"].level == Level.INHABITUEL
    feed(mon, "2.2.2.2", 30, t + 2, t + 8)
    feed(mon, "1.1.1.1", 30, t + 2, t + 8)
    mon.evaluate(t + 8)  # encore dans CALM_SECONDS
    assert mon.peers["1.1.1.1"].level == Level.INHABITUEL
    feed(mon, "2.2.2.2", 30, t + 8, t + 30)
    feed(mon, "1.1.1.1", 30, t + 8, t + 30)
    mon.evaluate(t + 30)
    assert mon.peers["1.1.1.1"].level == Level.NORMAL
    assert mon.peers["1.1.1.1"].alert == ""


# -- enregistrement : métadonnées uniquement -----------------------------------


def test_recorder_metadata_only(tmp_path):
    from guardian.network.recorder import HEADER, MetadataRecorder

    rec = MetadataRecorder(tmp_path)
    rec.write(1.0, "1.1.1.1", 10, True)  # inactif : ignoré
    path = rec.start()
    rec.write(2.5, "1.1.1.1", 100, True)
    rec.write(3.0, "2.2.2.2", 50, False)
    rec.stop()
    rows = list(csv.reader(path.open(encoding="utf-8")))
    assert tuple(rows[0]) == HEADER
    assert rows[1:] == [
        ["2.500000", "1.1.1.1", "100", "entrant"],
        ["3.000000", "2.2.2.2", "50", "sortant"],
    ]


# -- coût CPU borné ------------------------------------------------------------


def test_peer_cap_spoofed_flood():
    mon = SessionMonitor()
    for i in range(an.MAX_PEERS * 3):
        mon.add_packet(f"10.{i // 65536}.{i // 256 % 256}.{i % 256}", 50, 1.0)
    assert len(mon.peers) == an.MAX_PEERS
    mon.evaluate(1.0)
    # Une fois les anciens pairs inactifs, de nouveaux peuvent prendre leur place.
    mon.add_packet("99.99.99.99", 50, 1.0 + an.CONNECTED_SECONDS + 1)
    assert "99.99.99.99" in mon.peers
    assert len(mon.peers) == an.MAX_PEERS


def test_huge_uses_others_max_not_own():
    # Le plus gros émetteur est comparé au 2e max, les autres au 1er.
    mon = SessionMonitor()
    t = learned(mon, ["1.1.1.1", "2.2.2.2", "3.3.3.3"])
    feed(mon, "2.2.2.2", 30, t, t + 4, size=400)
    feed(mon, "3.3.3.3", 30, t, t + 4, size=300)
    feed(mon, "1.1.1.1", 30, t, t + 4, size=1400)
    mon.evaluate(t + 4)
    assert "énormes (1400 o, max des autres 400 o)" in mon.peers["1.1.1.1"].alert
    assert mon.peers["2.2.2.2"].level == Level.NORMAL


# -- enregistrement : rotation / limite -------------------------------------------


def test_recorder_rotates_and_stops(tmp_path):
    from guardian.network.recorder import MetadataRecorder

    rec = MetadataRecorder(tmp_path)
    rec.max_lines, rec.max_files = 10, 3
    rec.start()
    for i in range(100):
        rec.write(float(i), "1.1.1.1", 10, True)
    assert rec.stopped_by_limit and not rec.active
    files = sorted(tmp_path.glob("*.csv"))
    assert len(files) == 3
    for f in files:
        assert len(f.read_text(encoding="utf-8").splitlines()) == 11  # en-tête + 10


def test_recorder_byte_limit(tmp_path):
    from guardian.network.recorder import MetadataRecorder

    rec = MetadataRecorder(tmp_path)
    rec.max_bytes, rec.max_files = 1000, 1
    rec.start()
    for i in range(1000):
        rec.write(float(i), "1.1.1.1", 10, True)
    assert rec.stopped_by_limit
    assert next(tmp_path.glob("*.csv")).stat().st_size < 2000
