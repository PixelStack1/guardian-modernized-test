"""« Session publique en hôte au départ » : 60 s solo fixes, puis réouverture automatique."""

from unittest import mock

import pytest
from guardian.network import sessions as s

STRANGER = "203.0.113.50"
ROCKSTAR = "185.56.65.7"
JOIN_SIZES = [45, 125, 191, 205, 300, 500]


class Clock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


@pytest.fixture
def conn():
    return mock.MagicMock()


def make(conn, clock):
    return s.HostFirstSession(1, conn, clock=clock)


def test_duration_is_fixed_sixty_seconds():
    assert s.HOST_FIRST_SECONDS == 60
    import inspect

    params = inspect.signature(s.HostFirstSession).parameters
    assert "seconds" not in params and "duration" not in params  # aucun réglage


def test_open_at_is_now_plus_sixty(conn):
    clock = Clock()
    assert make(conn, clock).open_at == 1060.0


@pytest.mark.parametrize("size", JOIN_SIZES)
def test_joins_blocked_for_sixty_seconds(conn, packet_factory, size):
    clock = Clock()
    sess = make(conn, clock)
    for t in (0, 30, 59.9):
        clock.now = 1000.0 + t
        assert not sess.is_open()
        assert not sess.is_packet_allowed(
            packet_factory(src=STRANGER, payload=b"\1" * size)
        )


@pytest.mark.parametrize("size", JOIN_SIZES)
def test_reopens_after_sixty_seconds(conn, packet_factory, size):
    clock = Clock()
    sess = make(conn, clock)
    clock.now = 1060.0
    assert sess.is_open() and sess.finished() and sess.remaining() == 0
    assert sess.is_packet_allowed(packet_factory(src=STRANGER, payload=b"\1" * size))


@pytest.mark.parametrize("size", sorted(s.HEARTBEAT_SIZES))
def test_heartbeats_pass_in_phase_one(conn, packet_factory, size):
    sess = make(conn, Clock())
    assert sess.is_packet_allowed(packet_factory(src=STRANGER, payload=b"\0" * size))


@pytest.mark.parametrize("port", sorted(s.EXTRA_PORTS))
def test_rockstar_passes_in_phase_one(conn, packet_factory, port):
    sess = make(conn, Clock())
    assert s.is_rockstar_ip(ROCKSTAR)
    assert sess.is_packet_allowed(
        packet_factory(src=ROCKSTAR, dport=port, payload=b"\0" * 300)
    )
    assert not sess.is_packet_allowed(
        packet_factory(src=STRANGER, dport=port, payload=b"\0" * 300)
    )


def test_phase_one_matches_solo_exactly(conn, packet_factory):
    host, solo = make(conn, Clock()), s.SoloSession(1, conn)
    for src in (STRANGER, ROCKSTAR):
        for dport in (6672, *sorted(s.EXTRA_PORTS)):
            for size in (1, 12, 18, 45, 125, 191, 205, 300, 1200):
                p = packet_factory(src=src, dport=dport, payload=b"\0" * size)
                assert host.is_packet_allowed(p) == solo.is_packet_allowed(p)


def _run_with(packets, sess):
    handle = mock.MagicMock()
    handle.__iter__.return_value = iter(packets)
    with mock.patch.object(s.pydivert, "WinDivert", return_value=handle):
        sess.run()
    return handle


def test_run_drops_then_forwards_original_and_closes(conn, packet_factory):
    clock = Clock()
    sess = make(conn, clock)
    join1 = packet_factory(src=STRANGER, payload=b"\1" * 300)
    hb = packet_factory(src=STRANGER, payload=b"\0" * 12)
    join2 = packet_factory(src=STRANGER, payload=b"\1" * 300)
    never = packet_factory(src=STRANGER, payload=b"\1" * 300)
    before = [bytes(p.raw) for p in (join1, hb, join2)]

    def stream():
        yield join1  # phase 1 : jeté
        yield hb  # phase 1 : heartbeat, réinjecté
        clock.now = 1060.0
        yield join2  # phase 2 : réinjecté, puis fermeture du handle
        yield never  # jamais lu : le handle est fermé

    handle = _run_with(stream(), sess)
    sent = [c.args[0] for c in handle.send.call_args_list]
    assert sent == [hb, join2]
    assert all(
        a is b for a, b in zip(sent, [hb, join2], strict=True)
    )  # paquets originaux
    assert [bytes(p.raw) for p in (join1, hb, join2)] == before  # rien de modifié
    assert handle.close.called or handle.__exit__.called
    # Aucune autre API d'émission/fabrication utilisée.
    used = {c[0].split(".")[0] for c in handle.mock_calls if c[0]}
    assert used <= {
        "open",
        "send",
        "close",
        "__enter__",
        "__exit__",
        "__iter__",
        "recv",
        "is_open",
    }


def test_no_packet_constructor_in_session_code():
    import inspect

    src = inspect.getsource(s.HostFirstSession) + inspect.getsource(
        s.AbstractPacketFilter.run
    )
    assert "Packet(" not in src
    assert (
        src.count("w.send(") == 1 and "w.send(packet)" in src
    )  # paquet original uniquement


def test_countdown_then_session_open_message(conn):
    from guardian.menu.hostfirst import host_first_countdown

    clock = Clock()
    sess = make(conn, clock)
    lines = []

    def fake_sleep(sec):
        clock.now += sec

    host_first_countdown(sess, sleep=fake_sleep, out=lambda *a, **k: lines.append(a[0]))
    assert any("60 s" in ln for ln in lines) and any("1 s" in ln for ln in lines)
    assert lines[-1].startswith("Session ouverte")
    assert clock.now >= 1060.0


MENU_SRC = (
    __import__("pathlib").Path(__file__).parents[1] / "guardian/menu/menu.py"
).read_text(
    encoding="utf-8"
)  # lu comme texte : importer menu.py télécharge les plages R*/Azure


def test_menu_entry_and_i18n():
    from guardian.util import i18n

    assert (
        '{"name": t("menu.host_first"), "value": Menu.launch_host_first_session}'
        in MENU_SRC
    )
    assert 'HostFirstSession: ("menu.host_first", "explain.host_first")' in MENU_SRC
    assert i18n.STRINGS["menu.host_first"]["fr"] == "Session publique en hôte au départ"
    assert i18n.STRINGS["menu.host_first"]["en"] == "Public session, host first"
    assert i18n.STRINGS["host_first.opened"]["en"].startswith("Session open")


def test_not_active_unless_chosen_and_no_reopen_key():
    assert (
        MENU_SRC.count("HostFirstSession(") == 1
    )  # créé seulement par l'entrée de menu
    assert "open_at=" not in MENU_SRC  # pas de réouverture anticipée
