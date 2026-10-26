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

    titles = []
    host_first_countdown(
        sess,
        sleep=fake_sleep,
        out=lambda *a, **k: lines.append(a[0]),
        set_title=titles.append,
    )
    from guardian.util.console import get_original_console_title

    assert titles == [get_original_console_title()]  # titre d'origine remis à la fin
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


def test_uses_monotonic_clock_by_default(conn):
    import inspect
    import time

    assert (
        inspect.signature(s.HostFirstSession).parameters["clock"].default
        is time.monotonic
    )
    sess = s.HostFirstSession(1, conn)
    assert sess.duration == 60.0
    assert 59.0 < sess.remaining() <= 60.0


def test_filter_process_rearms_its_own_deadline(conn, packet_factory):
    """On transmet une durée : le processus de filtrage réarme open_at au démarrage."""
    clock = Clock(1000.0)
    sess = make(conn, clock)
    clock.now = (
        5000.0  # autre origine d'horloge (ex. autre processus) / démarrage tardif
    )
    join = packet_factory(src=STRANGER, payload=b"\1" * 300)
    handle = _run_with(iter([join]), sess)
    assert sess.open_at == 5060.0
    assert handle.send.call_count == 0  # toujours en phase 1 : join jeté


# -- signal « filtre lancé » ----------------------------------------------------


def test_filter_sends_started_after_handle_opened(conn, packet_factory):
    clock = Clock(1000.0)
    sess = make(conn, clock)
    order = []
    handle = mock.MagicMock()
    handle.__iter__.return_value = iter([])
    handle.open.side_effect = lambda *a: order.append("open")
    conn.send.side_effect = lambda msg: order.append(msg)
    clock.now = 2000.0
    with mock.patch.object(s.pydivert, "WinDivert", return_value=handle):
        sess.run()
    assert (s.HOST_FIRST_STARTED, 60.0) in order
    assert order.index("open") < order.index((s.HOST_FIRST_STARTED, 60.0))
    assert sess.open_at == 2060.0


def test_started_signal_failure_does_not_break_filter(conn):
    conn.send.side_effect = OSError("pipe fermé")
    sess = make(conn, Clock())
    sess.on_started()  # ne lève pas
    assert sess.open_at == 1060.0


def test_menu_waits_for_started_then_counts_from_it(conn):
    from multiprocessing import Pipe

    from guardian.menu.hostfirst import drain, wait_until_started

    parent, child = Pipe()
    child.send(True)  # ancien signal d'un autre filtre
    drain(parent)
    assert not parent.poll(0)
    clock = Clock(1000.0)
    sess = make(conn, clock)
    clock.now = 1003.0  # le filtre a mis 3 s à démarrer
    child.send(True)  # signal générique ignoré
    child.send((s.HOST_FIRST_STARTED, 60.0))
    assert wait_until_started(sess, parent, timeout=2)
    assert sess.open_at == 1063.0  # compte à rebours complet depuis le vrai lancement


def test_menu_starts_anyway_after_timeout(conn):
    from guardian.menu.hostfirst import START_TIMEOUT_SECONDS, wait_until_started

    assert START_TIMEOUT_SECONDS == 10.0

    class SilentConn:
        def poll(self, timeout):
            clock.now += timeout
            return False

    clock = Clock(1000.0)
    sess = make(conn, clock)
    assert not wait_until_started(sess, SilentConn(), timeout=10, clock=clock)
    assert clock.now >= 1010.0
    assert sess.open_at == clock.now + 60.0


def test_menu_survives_broken_pipe(conn):
    from guardian.menu.hostfirst import drain, wait_until_started

    class Broken:
        def poll(self, _t):
            raise OSError

    sess = make(conn, Clock())
    drain(Broken())
    assert not wait_until_started(sess, Broken(), timeout=1)


def test_menu_waits_before_countdown():
    i = MENU_SRC.index("def launch_host_first_session")
    body = MENU_SRC[i : MENU_SRC.index("@staticmethod", i)]
    assert body.index("start_latest_filter") < body.index("wait_until_started")
    assert body.index("wait_until_started") < body.index("host_first_countdown")


# -- durée annoncée validée, échecs du filtre, read_flag journalisé -------------


def _started_with(conn, payload):
    from multiprocessing import Pipe

    from guardian.menu.hostfirst import wait_until_started

    parent, child = Pipe()
    clock = Clock(1000.0)
    sess = make(conn, clock)
    child.send((s.HOST_FIRST_STARTED, payload))
    assert wait_until_started(sess, parent, timeout=2)
    return sess


@pytest.mark.parametrize(
    "bad",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
        -5.0,
        0,
        0.0,
        60.0001,
        3600,
        "30",
        None,
        True,
    ],
)
def test_invalid_announced_duration_falls_back(conn, bad):
    sess = _started_with(conn, bad)
    assert sess.open_at == 1000.0 + sess.duration == 1060.0


@pytest.mark.parametrize("good", [0.5, 30, 45.0, 60])
def test_valid_announced_duration_used(conn, good):
    assert _started_with(conn, good).open_at == 1000.0 + good


def test_read_flag_logs_exception_at_debug(caplog):
    import logging

    from guardian.menu import livesession as ls

    class Broken:
        @property
        def value(self):
            raise RuntimeError("boom")

    with caplog.at_level(logging.DEBUG, logger=ls.logger.name):
        assert ls.read_flag(Broken()) is False
    rec = [r for r in caplog.records if r.name == ls.logger.name]
    assert rec and rec[0].levelno == logging.DEBUG
    assert rec[0].exc_info and isinstance(rec[0].exc_info[1], RuntimeError)


def test_dead_process_raises_before_countdown(conn):
    from guardian.menu.hostfirst import FilterStartFailed, wait_until_started

    parent = mock.MagicMock()
    parent.poll.return_value = False
    with pytest.raises(FilterStartFailed):
        wait_until_started(
            make(conn, Clock()), parent, timeout=1, is_alive=lambda: False
        )


def test_process_exits_during_wait(conn):
    from guardian.menu.hostfirst import FilterStartFailed, wait_until_started

    clock = Clock(1000.0)
    alive = iter([True, True, False])

    class Silent:
        def poll(self, t):
            clock.now += t
            return False

    with pytest.raises(FilterStartFailed):
        wait_until_started(
            make(conn, clock),
            Silent(),
            timeout=10,
            clock=clock,
            is_alive=lambda: next(alive, False),
        )


def test_failure_message_from_child_raises(conn):
    from multiprocessing import Pipe

    from guardian.menu.hostfirst import FilterStartFailed, wait_until_started

    parent, child = Pipe()
    child.send((s.HOST_FIRST_FAILED, "OSError: access denied"))
    with pytest.raises(FilterStartFailed, match="access denied"):
        wait_until_started(
            make(conn, Clock()), parent, timeout=2, is_alive=lambda: True
        )


def test_child_sends_failure_when_windivert_open_fails(conn):
    sent = []
    conn.send.side_effect = sent.append
    sess = make(conn, Clock())
    with (
        mock.patch.object(s.pydivert, "WinDivert", side_effect=OSError("denied")),
        pytest.raises(Exception, match="denied"),
    ):
        sess.run()
    assert any(
        m[0] == s.HOST_FIRST_FAILED and "denied" in m[1]
        for m in sent
        if isinstance(m, tuple)
    )
    assert (s.HOST_FIRST_STARTED, 60.0) not in sent


def test_menu_shows_error_and_returns_on_failure():
    from guardian.util import i18n

    i = MENU_SRC.index("def launch_host_first_session")
    body = MENU_SRC[i : MENU_SRC.index("@staticmethod", i)]
    assert "is_alive=session.process.is_alive" in body
    j = body.index("except FilterStartFailed")
    rest = body[j:]
    assert (
        rest.index('t("host_first.failed")')
        < rest.index("return")
        < rest.index("host_first_countdown")
    )
    assert "WinDivert" in i18n.STRINGS["host_first.failed"]["fr"]
    assert "administrateur" in i18n.STRINGS["host_first.failed"]["fr"]
    assert "administrator" in i18n.STRINGS["host_first.failed"]["en"]


def test_failed_text_says_no_filter_active():
    from guardian.util import i18n

    assert "aucun filtre n'est actif" in i18n.STRINGS["host_first.failed"]["fr"]
    assert "no filter is active" in i18n.STRINGS["host_first.failed"]["en"]


@pytest.mark.parametrize("alive", [[False], [True, False]])
def test_dead_process_keeps_pending_failure_reason(conn, alive):
    from multiprocessing import Pipe

    from guardian.menu.hostfirst import FilterStartFailed, wait_until_started

    parent, child = Pipe()
    child.send((s.HOST_FIRST_FAILED, "FilterOpenError: access denied"))
    states = iter(alive)
    sess = make(conn, Clock())
    with pytest.raises(FilterStartFailed, match="FilterOpenError: access denied"):
        wait_until_started(
            sess, parent, timeout=0, is_alive=lambda: next(states, False)
        )


def test_dead_process_recv_errors_are_protected(conn):
    from guardian.menu.hostfirst import FilterStartFailed, wait_until_started

    for exc in (EOFError, OSError):
        broken = mock.MagicMock()
        broken.poll.return_value = True
        broken.recv.side_effect = exc
        with pytest.raises(FilterStartFailed, match="process not alive"):
            wait_until_started(make(conn, Clock()), broken, is_alive=lambda: False)
