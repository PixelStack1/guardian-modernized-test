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
    wd.assert_called_once_with(
        s.PACKET_FILTER, priority=7, flags=s.pydivert.Flag.DEFAULT
    )
    handle.open.assert_called_once()
    handle.close.assert_called_once()
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


# ---- Extra ports 61455-61458 + strict filter (E) ----
ROCKSTAR = "185.56.65.10"  # inside T2 EU fallback 185.56.64.0/22
ALL = sorted(s.ALL_PORTS)


def test_filter_exactly_five_ports():
    assert {6672, 61455, 61456, 61457, 61458} == s.ALL_PORTS
    f = s.packet_filter(True)
    assert (
        "udp.DstPort == 6672" in f
        and "udp.DstPort >= 61455" in f
        and "udp.DstPort <= 61458" in f
    )
    assert "tcp" not in f and f.startswith("udp and ")
    assert s.packet_filter(False) == s.PACKET_FILTER_6672_ONLY
    assert "61455" not in s.packet_filter(False)


def test_filter_evaluates_only_five_ports(packet_factory):
    """Evaluate the filter semantics with a tiny Python model of the WinDivert expression."""

    def matches(port):
        return port == 6672 or 61455 <= port <= 61458

    assert [p for p in range(1, 65536) if matches(p)] == ALL


def test_rockstar_ip_detection():
    assert s.is_rockstar_ip(ROCKSTAR)
    assert not s.is_rockstar_ip(STRANGER)


@pytest.mark.parametrize("port", ALL)
def test_whitelist_per_port(conn, packet_factory, port):
    sess = s.WhitelistSession({FRIEND}, 1, conn)
    assert sess.is_packet_allowed(
        packet_factory(src=FRIEND, dport=port, payload=b"\0" * 300)
    )
    assert not sess.is_packet_allowed(
        packet_factory(src=STRANGER, dport=port, payload=b"\0" * 300)
    )
    rock = sess.is_packet_allowed(
        packet_factory(src=ROCKSTAR, dport=port, payload=b"\0" * 300)
    )
    assert rock is (port in s.EXTRA_PORTS)


@pytest.mark.parametrize("port", ALL)
def test_solo_per_port(conn, packet_factory, port):
    sess = s.SoloSession(1, conn)
    hb = sess.is_packet_allowed(
        packet_factory(src=STRANGER, dport=port, payload=b"\0" * 12)
    )
    # heartbeat heuristic only on 6672
    assert hb is (port == 6672)
    assert sess.is_packet_allowed(
        packet_factory(src=ROCKSTAR, dport=port, payload=b"\0" * 300)
    ) is (port in s.EXTRA_PORTS)


@pytest.mark.parametrize("port", ALL)
def test_blacklist_per_port_never_blocks_rockstar(conn, packet_factory, port):
    from guardian.util.network import construct_cidr_block_set

    blocks = construct_cidr_block_set(["185.56.64.0/22", "198.51.100.0/24"])
    sess = s.BlacklistSession(set(), 1, conn, blocks=blocks)
    rock = sess.is_packet_allowed(
        packet_factory(src=ROCKSTAR, dport=port, payload=b"\0" * 300)
    )
    assert rock is (port in s.EXTRA_PORTS)
    assert not sess.is_packet_allowed(
        packet_factory(src="198.51.100.7", dport=port, payload=b"\0" * 300)
    )
    # heartbeat size from a blacklisted range only exempt on 6672
    hb = s.BlacklistSession(set(), 1, conn, blocks=blocks).is_packet_allowed(
        packet_factory(src="198.51.100.8", dport=port, payload=b"\0" * 12)
    )
    assert hb is (port == 6672)


@pytest.mark.parametrize("port", ALL)
def test_locked_per_port(conn, packet_factory, port):
    sess = s.LockedSession(1, conn)
    mm = sess.is_packet_allowed(
        packet_factory(src=STRANGER, dport=port, payload=b"\0" * 191)
    )
    assert mm is (port in s.EXTRA_PORTS)  # matchmaking heuristic only on 6672


def test_extra_ports_config_option(conn):
    from config.configdata import ConfigData

    cfg = ConfigData()
    cfg.data["extra_ports"] = False
    try:
        assert s.extra_ports_enabled() is False
        assert s.WhitelistSession(set(), 1, conn).extra_ports is False
    finally:
        cfg.data["extra_ports"] = True
    assert s.extra_ports_enabled() is True


def test_run_uses_6672_only_filter_when_disabled(conn):
    handle = mock.MagicMock()
    handle.__iter__.return_value = iter([])
    with mock.patch.object(s.pydivert, "WinDivert", return_value=handle) as wd:
        sess = s.SoloSession(3, conn)
        sess.extra_ports = False
        sess.run()
    assert wd.call_args.args[0] == s.PACKET_FILTER_6672_ONLY


def test_open_failure_raises_filter_open_error():
    handle = mock.MagicMock()
    handle.open.side_effect = OSError(87, "invalid filter")
    with (
        mock.patch.object(s.pydivert, "WinDivert", return_value=handle),
        pytest.raises(s.FilterOpenError),
    ):
        s.probe_filter()


def test_constructor_failure_raises_filter_open_error():
    with (
        mock.patch.object(s.pydivert, "WinDivert", side_effect=OSError(5, "denied")),
        pytest.raises(s.FilterOpenError, match="denied"),
    ):
        s.probe_filter(False)


@pytest.mark.parametrize("port", sorted(s.EXTRA_PORTS))
def test_extra_ports_outbound_not_extra(packet_factory, port):
    assert s.is_extra_port(packet_factory(dport=port, inbound=True))
    assert not s.is_extra_port(packet_factory(dport=port, inbound=False))
    assert not s.is_extra_port(packet_factory(dport=6672, inbound=True))
