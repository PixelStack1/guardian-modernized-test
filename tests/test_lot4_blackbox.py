"""Lot 4 : boîte noire (dernières secondes, métadonnées seules)."""

import csv
import io
import queue as q
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import replay as rp
from menu import livesession as ls
from network import blackbox as bb
from network.recorder import HEADER

FIXTURE = Path(__file__).parent / "fixtures" / "kick_lot4.csv"
SECRET = b"SECRET-PAYLOAD-DO-NOT-LEAK"


def meta(ts, ip="198.51.100.7", inbound=True, passed=True, reason=""):
    src, dst = (ip, "192.168.1.2") if inbound else ("192.168.1.2", ip)
    return bb.PacketMeta(ts, src, 6672, dst, 6672, "udp", 100, inbound, passed, reason)


def box(tmp_path, **kw):
    kw.setdefault("threaded", False)
    kw.setdefault("seconds", 30)
    return bb.BlackBox(tmp_path, clock=lambda: 0.0, **kw)


def test_packet_meta_has_no_payload_field():
    assert not any("payload" in f or "data" in f for f in bb.PacketMeta._fields)


def test_meta_from_packet_keeps_only_length(packet_factory):
    pkt = packet_factory(src="198.51.100.7", payload=SECRET, sport=1234)
    m = bb.meta_from_packet(pkt, 5.0, False, bb.R_LOCK)
    assert m.size == len(SECRET) and m.sport == 1234 and m.proto == "udp"
    assert m.src == "198.51.100.7" and m.inbound and not m.passed
    assert all(not isinstance(v, bytes) for v in m)
    assert SECRET.decode() not in ",".join(m.row())
    assert bb.meta_from_packet(pkt, 5.0, True, bb.R_LOCK).reason == ""


def test_window_before_and_after_written_after_delay(tmp_path):
    b = box(tmp_path, seconds=10)
    for ts in range(0, 100):
        b.add(meta(float(ts)))
    assert b.trigger("manuel", now=50.0)
    assert not b.written  # fenêtre « après » pas encore écoulée
    b.add(meta(100.0))  # dépasse 60 -> écrit
    assert len(b.written) == 1
    rows = list(csv.reader(b.written[0].open(encoding="utf-8")))
    assert tuple(rows[0]) == bb.FULL_HEADER
    stamps = [float(r[0]) for r in rows[1:]]
    assert min(stamps) == 40.0 and max(stamps) == 60.0 and len(stamps) == 21


def test_tick_without_packets_writes(tmp_path):
    b = box(tmp_path, seconds=5)
    b.add(meta(1.0))
    b.trigger("manuel", now=1.0)
    b.tick(10.0)
    assert len(b.written) == 1


def test_overlapping_and_auto_cooldown(tmp_path):
    b = box(tmp_path)
    assert b.trigger("verrou", 0.0, auto=True)
    assert not b.trigger("manuel", 10.0)  # couvert par la capture en attente
    b.tick(31.0)
    assert not b.trigger("verrou", 40.0, auto=True)  # cooldown
    assert b.trigger("verrou", 100.0, auto=True)


def test_memory_bound(tmp_path):
    b = box(tmp_path, max_entries=50)
    for i in range(500):
        b.add(meta(float(i)))
    assert len(b.buffer) == 50 and b.buffer[0].ts == 450.0


def test_disk_rotation_keeps_max_files(tmp_path):
    b = box(tmp_path, max_files=3, seconds=1)
    for i in range(6):
        b.add(meta(i * 10.0))
        b.trigger("manuel", now=i * 10.0)
        b.tick(i * 10.0 + 2)
    files = sorted(tmp_path.glob("kick-*.csv"))
    assert len(files) == 3
    assert not list(tmp_path.glob(".tmp-*"))  # écriture atomique : aucun reste


def test_write_error_never_raises(tmp_path):
    target = tmp_path / "f"
    target.write_text("pas un dossier")
    b = bb.BlackBox(target, threaded=False, seconds=1)
    b.add(meta(0.0))
    b.trigger("manuel", now=0.0)
    b.tick(5.0)  # mkdir sur un fichier -> erreur avalée
    assert b.errors >= 1 and not b.written


def test_flush_threaded(tmp_path):
    b = bb.BlackBox(tmp_path, seconds=30, clock=lambda: 0.0)
    b.add(meta(0.0))
    b.trigger("manuel", now=0.0)
    b.flush()
    assert len(list(tmp_path.glob("kick-*.csv"))) == 1


@pytest.mark.parametrize(
    "raw,expected",
    [(None, 30), ("10", 30), (True, 30), (10, 10), (0, 1), (10_000, 300), (12.7, 12)],
)
def test_clamp_seconds(raw, expected):
    assert bb.clamp_seconds(raw) == expected


def test_drop_reason_read_only():
    pol = ls.LivePolicy(lock_on=True)
    assert bb.drop_reason(True, "x", {}, {}, 0, False, False, pol) == bb.R_LOCK
    assert pol.seen == set()
    pol = ls.LivePolicy(offenders=frozenset({"x"}), offender_drop=True)
    assert bb.drop_reason(True, "x", {}, {}, 0, False, False, pol) == bb.R_OFFENDER
    assert bb.drop_reason(True, "x", {"x": 0.0}, {}, 0, False, False, None) == (
        bb.R_BLOCKED
    )
    assert bb.drop_reason(False, "x", {}, {"x": 9}, 0, True, False, None) == bb.R_TOTAL
    assert bb.drop_reason(True, "x", {}, {}, 0, False, True, None) == bb.R_RELAY
    assert bb.drop_reason(True, "x", None, {}, 0, False, False, None) == bb.R_UNKNOWN


@settings(max_examples=60, deadline=None)
@given(
    st.lists(
        st.tuples(
            st.floats(0, 1e6, allow_nan=False),
            st.ip_addresses(v=4).map(str),
            st.booleans(),
            st.booleans(),
        ),
        max_size=60,
    ),
    st.integers(1, 40),
)
def test_hypothesis_bounded_and_replayable(tmp_path_factory, items, cap):
    d = tmp_path_factory.mktemp("bb")
    b = bb.BlackBox(d, threaded=False, max_entries=cap, seconds=300, max_files=2)
    for ts, ip, inbound, passed in sorted(items):
        b.add(meta(ts, ip, inbound, passed, "" if passed else bb.R_LOCK))
        assert len(b.buffer) <= cap
    b.trigger("manuel", now=items[-1][0] if items else 0.0)
    b.flush()
    assert len(list(d.glob("kick-*.csv"))) <= 2
    for f in d.glob("kick-*.csv"):
        rows = list(rp.read_rows(f.open(encoding="utf-8")))
        assert len(rows) <= cap


def test_replay_reads_fixture():
    rows = list(rp.read_rows(FIXTURE.open(encoding="utf-8")))
    assert len(rows) == 6
    assert all(
        ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")) for _t, ip, *_ in rows
    )
    out: list[str] = []
    res = rp.replay(rows, emit=out.append)
    assert res.packets == 6


def test_replay_main_on_fixture():
    assert rp.main([str(FIXTURE)]) == 0


def test_replay_still_reads_4_column_format():
    text = ",".join(HEADER) + "\n1.0,192.0.2.1,10,entrant\n1.0,192.0.2.1,10,entrant,x\n"
    assert len(list(rp.read_rows(io.StringIO(text)))) == 1


def test_handle_key_k(tmp_path):
    ctrl = ls.LiveSessionController({}, _BL())
    b = box(tmp_path)
    ls.handle_key("k", ctrl, [], {}, None, lambda _p: "", blackbox=b)
    assert b.pending and "30" in ctrl.events[-1]
    ls.handle_key("k", ctrl, [], {}, None, lambda _p: "", blackbox=b)
    assert len(b.pending) == 1
    ls.handle_key("k", ctrl, [], {}, None, lambda _p: "")
    assert len(ctrl.events) == 3


class _BL:
    def __iter__(self):
        return iter([])

    def add(self, *a):
        pass

    def save(self):
        pass


class _Rec:
    active = False

    def write(self, *a):
        pass

    def stop(self):
        pass


def test_background_feeds_and_auto_triggers_on_lock_drop(tmp_path):
    from network.anomaly import SessionMonitor

    packets: q.Queue = q.Queue()
    ip = "198.51.100.9"
    packets.put((1.0, ip, 100, True, 6672))  # ancien format (5) toléré
    packets.put(
        (2.0, ip, 100, True, 6672, meta(2.0, ip, passed=False, reason="verrou"))
    )
    packets.put((3.0, ip, 100, True, 6672, "pas une meta"))  # ignoré sans erreur
    ctrl = ls.LiveSessionController({}, _BL())
    b = box(tmp_path)
    s = ls.BackgroundSession(
        None, packets, ctrl, SessionMonitor(), ls.PlayerCounter(), _Rec(), blackbox=b
    )
    for _ in range(3):
        s.step(0.01)
    assert len(b.buffer) == 1 and b.pending and b.pending[0][1] == "verrou"
    assert any("verrou" in e for e in ctrl.events)
    s.stop()  # flush
    assert len(list(tmp_path.glob("kick-*-verrou.csv"))) == 1


def test_handle_packet_sends_original_only_once(packet_factory):
    class W:
        def __init__(self):
            self.sent = []

        def send(self, p):
            self.sent.append(p)

    w = W()
    pkt = packet_factory(payload=SECRET)
    assert ls.handle_packet(w, pkt, {}, {}, 0.0)
    assert w.sent == [pkt] and bytes(pkt.payload) == SECRET


def test_capture_loop_source_send_unchanged():
    import inspect

    src = inspect.getsource(ls.capture_loop)
    assert ".send(" not in src.split("handle_packet(", 1)[1]
    assert "payload)" in src and "meta_from_packet" in src
