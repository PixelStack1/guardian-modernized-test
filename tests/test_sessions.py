from unittest import mock

import pytest
from guardian.network import sessions as s
from guardian.util.network import construct_cidr_block_set

FRIEND = "198.51.100.7"
STRANGER = "203.0.113.10"


@pytest.fixture
def conn():
    return mock.Mock()


def test_packet_factory_roundtrip(packet_factory):
    p = packet_factory(src=FRIEND, payload=b"x" * 12)
    assert p.ip.src_addr == FRIEND
    assert len(p.payload) == 12
    assert p.is_inbound and p.dst_port == 6672


@pytest.mark.parametrize("size", sorted(s.HEARTBEAT_SIZES))
def test_solo_allows_heartbeat(conn, packet_factory, size):
    f = s.SoloSession(1, conn)
    assert f.is_packet_allowed(packet_factory(payload=b"\0" * size))


@pytest.mark.parametrize("size", [1, 45, 125, 191, 205, 500])
def test_solo_blocks_everything_else(conn, packet_factory, size):
    f = s.SoloSession(1, conn)
    assert not f.is_packet_allowed(packet_factory(payload=b"\0" * size))


def test_whitelist_allows_friend_any_size(conn, packet_factory):
    f = s.WhitelistSession({FRIEND}, 1, conn)
    for size in (1, 2, 4, 45, 300, 1200):
        assert f.is_packet_allowed(packet_factory(src=FRIEND, payload=b"\x01" * size))


def test_whitelist_blocks_stranger(conn, packet_factory):
    f = s.WhitelistSession({FRIEND}, 1, conn)
    assert not f.is_packet_allowed(packet_factory(payload=b"\x01" * 300))
    assert f.is_packet_allowed(packet_factory(payload=b"\x01" * 18))  # heartbeat


@pytest.mark.parametrize("size", [1, 2, 3, 4])
def test_whitelist_tiny_payload_no_crash(conn, packet_factory, size):
    # Regression: upstream 3.5.0 raised IndexError on payload[4] here, killing the filter.
    f = s.WhitelistSession(set(), 1, conn)
    assert f.is_packet_allowed(packet_factory(payload=b"\x07" * size)) is False


def _service_payload(size: int, offset: int, magic: int, code: int) -> bytes:
    buf = bytearray(size)
    buf[0:2] = size.to_bytes(2, "big")
    buf[4] = magic
    buf[2] = offset ^ magic
    m2 = int.from_bytes(bytes([magic, magic]), "big")
    pos = 25 if offset == 17 else 89
    buf[pos : pos + 2] = (code ^ m2).to_bytes(2, "big")
    if offset == 17:
        buf[24] = 0xAA ^ magic  # alt not in KNOWNS
    return bytes(buf)


@pytest.mark.parametrize("offset,size", [(17, 40), (49, 120)])
@pytest.mark.parametrize("code", [0xFEFF, 0xFEFD, 0x0003])
def test_whitelist_service_heuristic_allows(conn, packet_factory, offset, size, code):
    f = s.WhitelistSession(set(), 1, conn)
    pl = _service_payload(size, offset, 0x5C, code)
    assert s.is_whitelist_service_packet(pl)
    assert f.is_packet_allowed(packet_factory(payload=pl))


def test_whitelist_service_heuristic_alt_knowns(packet_factory):
    pl = bytearray(_service_payload(40, 17, 0x33, 0x1234))
    pl[24] = 0x39 ^ 0x33
    assert s.is_whitelist_service_packet(bytes(pl))


def test_whitelist_service_heuristic_rejects(packet_factory):
    assert not s.is_whitelist_service_packet(_service_payload(40, 17, 0x5C, 0x1234))
    pl = bytearray(_service_payload(40, 17, 0x5C, 0xFEFF))
    pl[0:2] = (41).to_bytes(2, "big")  # wrapper length mismatch
    assert not s.is_whitelist_service_packet(bytes(pl))


def test_heuristic_matches_upstream_raw_offset(packet_factory):
    # upstream used packet.raw[28:30]; for a 20-byte IPv4 header it equals payload[0:2]
    p = packet_factory(payload=_service_payload(40, 17, 0x5C, 0xFEFF))
    assert bytes(p.raw[28:30]) == bytes(p.payload[0:2])


def test_blacklist(conn, packet_factory):
    blocks = construct_cidr_block_set(["203.0.113.0/24"])
    f = s.BlacklistSession({"192.0.2.1"}, 1, conn, blocks=blocks)
    assert not f.is_packet_allowed(packet_factory(src="192.0.2.1", payload=b"\0" * 300))
    assert not f.is_packet_allowed(packet_factory(src=STRANGER, payload=b"\0" * 300))
    assert STRANGER in f.ips  # cached as blacklisted
    assert f.is_packet_allowed(packet_factory(src=FRIEND, payload=b"\0" * 300))
    assert FRIEND in f.known_allowed
    # heartbeat / matchmaking sizes always pass
    assert f.is_packet_allowed(packet_factory(src=STRANGER, payload=b"\0" * 12))


@pytest.mark.parametrize("size", sorted(s.MATCHMAKING_SIZES))
def test_locked_blocks_matchmaking(conn, packet_factory, size):
    assert not s.LockedSession(1, conn).is_packet_allowed(
        packet_factory(payload=b"\0" * size)
    )


def test_locked_allows_game_traffic(conn, packet_factory):
    assert s.LockedSession(1, conn).is_packet_allowed(
        packet_factory(payload=b"\0" * 300)
    )


def test_packet_filter_string():
    assert "6672" in s.PACKET_FILTER and "udp" in s.PACKET_FILTER


def test_run_loop_reinjects_only_allowed(conn, packet_factory):
    """Mock WinDivert handle: allowed packets are re-sent, dropped ones are not."""
    good = packet_factory(src=FRIEND, payload=b"\0" * 300)
    bad = packet_factory(src=STRANGER, payload=b"\0" * 300)
    handle = mock.MagicMock()
    handle.__enter__.return_value = handle
    handle.__iter__.return_value = iter([good, bad])
    with mock.patch.object(s.pydivert, "WinDivert", return_value=handle) as wd:
        s.WhitelistSession({FRIEND}, 7, conn).run()
    wd.assert_called_once_with(s.PACKET_FILTER, priority=7)
    handle.send.assert_called_once_with(good)
    conn.send.assert_called_once_with(True)


def test_ip_collector_counts_only_non_service_inbound(packet_factory):
    handle = mock.MagicMock()
    handle.__enter__.return_value = handle
    pkts = [
        packet_factory(src=FRIEND, payload=b"\0" * 300),
        packet_factory(src=FRIEND, payload=b"\0" * 300),
        packet_factory(src=STRANGER, payload=b"\0" * 12),  # heartbeat -> ignored
        packet_factory(src=STRANGER, payload=b"\0" * 300, inbound=False),
    ]
    handle.__iter__.return_value = iter(pkts)
    with mock.patch.object(s, "Manager") as mgr:
        mgr.return_value.list.return_value = []
        mgr.return_value.dict.return_value = {}
        c = s.IPCollector(1, packet_count_min_threshold=2)
    with mock.patch.object(s.pydivert, "WinDivert", return_value=handle):
        c.run()
    c.save_ips()
    assert c.seen_ips == {FRIEND: 2}
    assert c.ips == [FRIEND]
