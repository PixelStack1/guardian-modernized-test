"""Mode « blocage total » : coupure SORTANTE 10 min vers l'IP bloquée, drop uniquement."""

import pytest
from guardian.menu import livesession as ls
from guardian.network.anomaly import Level, PeerState
from guardian.util import dynamicblacklist as dbl

ME, FOE, OTHER = "192.168.1.10", "203.0.113.5", "203.0.113.6"


class FakeList(dict):
    def __iter__(self):
        return iter(self.items())

    def add(self, ip, name):
        self[ip] = name

    def remove(self, ip):
        del self[ip]

    def save(self):
        pass


class Ip:
    def __init__(self, src, dst):
        self.src_addr, self.dst_addr = src, dst


class FakePacket:
    """Paquet figé : toute tentative de modification échoue le test."""

    def __init__(self, src, dst, inbound):
        object.__setattr__(self, "ip", Ip(src, dst))
        object.__setattr__(self, "is_inbound", inbound)
        object.__setattr__(self, "is_outbound", not inbound)

    def __setattr__(self, *_a):
        raise AssertionError("paquet modifié")


class FakeHandle:
    """Seule méthode disponible : send() ; aucune autre API d'émission."""

    def __init__(self):
        self.sent = []

    def send(self, packet):
        self.sent.append(packet)


def ctrl_for(total=True, available=True, guard=None, clock=None):
    clock = clock or [1000.0]
    c = ls.LiveSessionController(
        {},
        FakeList(),
        auto_block=True,
        clock=lambda: clock[0],
        auto_block_guard=guard,
        auto_block_available=available,
        total_block=total,
    )
    return c, clock


def test_constants_and_off_by_default():
    assert ls.TOTAL_BLOCK_SECONDS == 600
    assert ls.TOTAL_BLOCK_DEFAULT is False
    c = ls.LiveSessionController({}, FakeList())
    assert not c.total_block
    c.block(FOE)
    assert c.total_blocked == {}  # OFF : seul l'entrant est bloqué


def test_direction_only_target_outbound_dropped():
    c, clock = ctrl_for()
    c.block(FOE)
    w = FakeHandle()
    now = clock[0] + 1
    out_foe = FakePacket(ME, FOE, inbound=False)
    out_other = FakePacket(ME, OTHER, inbound=False)
    in_foe = FakePacket(FOE, ME, inbound=True)
    in_other = FakePacket(OTHER, ME, inbound=True)
    results = [
        ls.handle_packet(w, p, c.blocked, c.total_blocked, now)
        for p in (out_foe, out_other, in_foe, in_other)
    ]
    assert results == [False, True, False, True]
    assert w.sent == [out_other, in_other]  # objets originaux, identiques
    assert all(a is b for a, b in zip(w.sent, [out_other, in_other], strict=True))


def test_outbound_passes_when_mode_off():
    c, clock = ctrl_for(total=False)
    c.block(FOE)
    w = FakeHandle()
    pkt = FakePacket(ME, FOE, inbound=False)
    assert ls.handle_packet(w, pkt, c.blocked, c.total_blocked, clock[0])
    assert w.sent == [pkt]


def test_expires_after_ten_minutes_inbound_continues():
    c, clock = ctrl_for()
    assert c.auto_block_if_needed(PeerState(FOE, 0, 0, level=Level.SUSPECT))
    assert c.total_blocked[FOE] == 1000.0 + 600
    assert ls.should_drop(False, ME, FOE, c.blocked, c.total_blocked, 1000.0 + 599)
    clock[0] = 1000.0 + 600
    c.expire()
    assert FOE not in c.total_blocked
    assert not ls.should_drop(False, ME, FOE, c.blocked, c.total_blocked, clock[0])
    assert ls.should_drop(True, FOE, ME, c.blocked, c.total_blocked, clock[0])  # 7 j
    assert c.blocked[FOE] == 1000.0 + ls.AUTO_BLOCK_SECONDS


def test_stale_entry_ignored_by_capture_even_before_purge():
    blocked = {FOE: ls.PERMANENT}
    assert not ls.should_drop(False, ME, FOE, blocked, {FOE: 999.0}, 1000.0)


def test_outbound_cut_requires_inbound_block():
    assert not ls.should_drop(False, ME, FOE, {}, {FOE: 9e9}, 1000.0)


def test_key_d_lifts_outbound_cut():
    c, clock = ctrl_for()
    c.block(FOE)
    c.unblock(FOE)
    assert FOE not in c.total_blocked and FOE not in c.blocked
    w = FakeHandle()
    pkt = FakePacket(ME, FOE, inbound=False)
    assert ls.handle_packet(w, pkt, c.blocked, c.total_blocked, clock[0])


def test_guards_whitelist_rockstar_azure():
    import ipaddress

    from guardian.network.sessions import ROCKSTAR_BLOCKS
    from guardian.util.network import construct_cidr_block_set

    rockstar = str(ipaddress.IPv4Address(next(iter(ROCKSTAR_BLOCKS))[0]))
    guard = ls.make_auto_block_guard({OTHER}, construct_cidr_block_set(["20.0.0.0/8"]))
    c, _ = ctrl_for(guard=guard)
    for ip in (OTHER, rockstar, "20.1.2.3"):
        c.block(ip)  # le manuel bloque l'entrant...
        assert ip in c.blocked
        assert ip not in c.total_blocked  # ...mais jamais la coupure sortante
    assert "protégée" in c.events[-1]


def test_unavailable_without_ranges():
    c, _ = ctrl_for(available=False)
    assert not c.total_block
    c.toggle_total_block()
    assert not c.total_block
    c.block(FOE)
    assert c.total_blocked == {}


def test_toggle():
    c, _ = ctrl_for(total=False)
    c.toggle_total_block()
    assert c.total_block
    c.toggle_total_block()
    assert not c.total_block


def test_fail_safe_errors_let_packet_through():
    class Broken(dict):
        def get(self, *_a):
            raise RuntimeError

    assert not ls.should_drop(False, ME, FOE, {FOE: 0.0}, Broken(), 1.0)

    class BadPacket:
        @property
        def is_inbound(self):
            raise RuntimeError

    w = FakeHandle()
    bad = BadPacket()
    assert ls.handle_packet(w, bad, {}, {}, 1.0) and w.sent == [bad]


def test_render_shows_status_and_warning():
    from guardian.network.anomaly import SessionMonitor

    c, _ = ctrl_for()
    out = ls.render(SessionMonitor(), c, [], "off", 0.0)
    assert "Blocage total" in out and "10 min" in out
    assert "pas un kick garanti" in out and "l'hôte" in out
    assert "[T]" in out


def test_no_packet_creation_api_used():
    """Le module n'importe ni ne construit de paquet (pydivert.Packet) : drop ou send() seulement."""
    import inspect

    src = inspect.getsource(ls)
    assert "Packet(" not in src.replace("FakePacket(", "")
    assert "pydivert" not in src
    calls = [ln.strip() for ln in src.splitlines() if ".send(" in ln and "``" not in ln]
    assert calls == ["w.send(packet)"]  # un seul envoi : le paquet original reçu


def test_dynamic_blacklist_requests_have_timeout(monkeypatch):
    seen = {}

    class Resp:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def raise_for_status(self):
            pass

        def iter_content(self, chunk_size):
            return [b"ok"]

    def fake_get(url, **kw):
        seen.update(kw)
        return Resp()

    monkeypatch.setattr(dbl.requests, "get", fake_get)
    assert dbl.get_capped("https://example.invalid", 10) == b"ok"
    assert seen["timeout"] == dbl.REQUEST_TIMEOUT == 15


@pytest.mark.parametrize("exc", ["Timeout", "ConnectionError"])
def test_ripe_timeout_falls_back(monkeypatch, tmp_path, exc):
    def boom(*_a, **_k):
        raise getattr(dbl.requests.exceptions, exc)()

    monkeypatch.setattr(dbl.requests, "get", boom)
    assert dbl.get_announced_prefixes(1, {"203.0.113.0/24"}, cache_dir=tmp_path) == {
        "203.0.113.0/24"
    }
