"""Serveurs Rockstar/Take-Two : reconnus (plages statiques), jamais joueurs ni bloqués."""

import sys

import pytest
from guardian.menu import livesession as ls
from guardian.network.anomaly import Level, PeerState, SessionMonitor
from tests.test_livescreen import FakeRecorder
from tests.test_totalblock import FakeList

R_EU = "185.56.65.171"  # RIPE EU-T2OE-185-56-65, AS202021 Take-Two
R_US = "164.153.137.10"  # ARIN RSONET-NA4, AS46555 Take-Two
PLAYER = "203.0.113.5"


def rt():
    return sys.modules[ls.t.__module__]


@pytest.mark.parametrize(
    "ip",
    [
        R_EU,
        R_US,
        "185.56.64.1",
        "185.56.67.254",
        "104.255.107.9",
        "192.81.247.1",
        "198.133.210.3",
    ],
)
def test_rockstar_ranges(ip):
    assert ls.is_rockstar_server(ip)


@pytest.mark.parametrize(
    "ip", [PLAYER, "185.56.68.1", "164.153.140.1", "8.8.8.8", "bad", ""]
)
def test_not_rockstar(ip):
    assert not ls.is_rockstar_server(ip)


def test_no_network_at_lookup(monkeypatch):
    import socket

    def boom(*_a, **_k):
        raise AssertionError("appel réseau")

    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(ls, "_ROCKSTAR_BLOCKS", None)
    assert ls.is_rockstar_server(R_EU)


def ctrl(**kw):
    return ls.LiveSessionController(
        {},
        FakeList(),
        auto_block=True,
        auto_block_available=True,
        auto_block_guard=lambda _ip: False,  # même sans garde, le serveur est protégé
        clock=lambda: 1000.0,
        total_block=True,
        **kw,
    )


def test_counted_separately_and_header():
    c = ls.PlayerCounter()
    ls.note_player(c, R_EU, inbound=True)
    ls.note_player(c, PLAYER, inbound=True)
    assert c.players() == [PLAYER] and c.server_count() == 1
    rt().set_language("fr", persist=False)
    line = ls.players_line(c, ctrl())
    assert line.startswith("Joueurs : 1 (") and "serveurs Rockstar 1" in line
    rt().set_language("en", persist=False)
    try:
        assert "Rockstar servers 1" in ls.players_line(c, ctrl())
    finally:
        rt().set_language("fr", persist=False)


def suspect(ip):
    p = PeerState(ip, 0.0, 0.0)
    p.level = Level.SUSPECT
    return p


def test_never_auto_blocked_nor_total_cut():
    k = ctrl()
    assert k.auto_block_if_needed(suspect(R_EU)) is False
    assert R_EU not in k.blocked and R_EU not in k.total_blocked
    k._cut_outbound(R_US)
    assert R_US not in k.total_blocked


def test_manual_block_refused_with_message():
    k = ctrl()
    k.block(R_EU, "x")
    assert R_EU not in k.blocked and R_EU not in dict(k.blacklist)
    assert "serveur Rockstar" in k.events[-1]

    asked = []

    def prompt(text):
        asked.append(text)
        return "1"

    ls.handle_key("b", k, [suspect(R_EU)], {}, FakeRecorder(), prompt)
    assert len(asked) == 1  # pas de demande de pseudo
    assert R_EU not in k.blocked


def test_render_labels_server_row():
    out = ls.render(SessionMonitor(), ctrl(), [suspect(R_EU)], "off", 0.0)
    row = next(x for x in out.split("\n") if R_EU in x)
    assert "serveur Rockstar" in row


@pytest.mark.parametrize("lang", ["fr", "en"])
def test_key_bar_fits_100_columns(lang):
    rt().set_language(lang, persist=False)
    try:
        assert len(ls.t("live.keys")) <= 100
    finally:
        rt().set_language("fr", persist=False)
