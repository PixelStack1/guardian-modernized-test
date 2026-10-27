"""Lot 5 / G1 : changer seuil/délai du bouclier en cours de session (set_shield)."""

import pytest

from network.anomaly import RATE_CAP, SessionMonitor

IP = "198.51.100.89"


def cut_after(before: float, after: float, pps: int, shield_pps: int = 80) -> float:
    """Délai (s) entre le changement de réglage et la coupure, à ``pps`` constant."""
    mon = SessionMonitor(shield_pps, before)
    t = 0.0
    while t < 10.0:  # IP déjà connue, débit bas
        mon.add_packet(IP, 100, t)
        t += 0.5
    mon.set_shield(shield_pps, after)
    start, dt = t, 1.0 / pps
    while t < start + 120.0:
        mon.add_packet(IP, 100, t)
        t += dt
        if mon.sustained(mon.peers[IP], t):
            return t - start
    return float("inf")


def test_set_shield_recomputes_slices_and_retention():
    mon = SessionMonitor(80, 5)
    assert (mon.slices, mon.retention) == (5, 5.0)
    mon.set_shield(5000, 0.2)  # rebornés : 1000 pkt/s, 1 s
    assert (mon.shield_pps, mon.shield_seconds) == (1000, 1.0)
    assert (mon.slices, mon.retention) == (3, 3.0)
    mon.set_shield(80, 60)
    assert (mon.slices, mon.retention) == (60, 60.0)


def test_5_to_60_s_cuts_around_60_s():
    # Règle normale (fenêtre de 60 s) à 100 pkt/s : coupure vers 60 s.
    assert 55.0 <= cut_after(5, 60, 100) <= 61.0
    # 300 pkt/s : la mémoire bornée (8192 horodatages) sature avant 60 s
    # (8192 / 300 ≈ 27 s) ; règle de saturation inchangée.
    assert cut_after(5, 60, 300) == pytest.approx(RATE_CAP / 300, abs=1.0)


def test_60_to_5_s_cuts_around_5_s_not_58():
    assert cut_after(60, 5, 300) <= 5.5
    assert cut_after(60, 5, 100) <= 5.5


def test_shrinking_window_forgets_old_timestamps():
    mon = SessionMonitor(80, 60)
    for k in range(6000):
        mon.add_packet(IP, 100, k * 0.01)  # 60 s à 100 pkt/s
    mon.set_shield(80, 5)
    assert len(mon.peers[IP].rate_ts) <= 5 * 100 + 1


def test_apply_settings_uses_set_shield():
    from tests.gui_fakes import FakeConfig, make_session

    from gui import core

    session = make_session(None, FakeConfig())
    act = core.GuiActions(session)
    act.apply_settings(core.Settings(shield_pps=100, shield_seconds=60))
    assert (session.monitor.slices, session.monitor.retention) == (60, 60.0)
    act.apply_settings(core.Settings(shield_pps=100, shield_seconds=5))
    assert (session.monitor.slices, session.monitor.retention) == (5, 5.0)
