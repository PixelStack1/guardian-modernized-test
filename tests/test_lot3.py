"""Lot 3 : pays, ping estimé, débit, badge VPN, correctifs d'audit F1-F5."""

import gzip
import json
import os
import time
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

import replay as rp
from menu import livesession as ls
from network import blackbox as bb
from network import filters as fl
from network.offenders import MAX_FILE_BYTES, OffenderStore, _parse
from util import paths, vpn
from util.i18n import t

FIXTURE = Path(__file__).parent / "fixtures" / "session_lot3.csv"
FR = "90.0.0.1"  # France, pas VPN
FR_VPN = "51.38.0.1"  # OVH France
US = "8.8.8.8"  # États-Unis, pas VPN
AU_VPN = "1.1.1.1"  # Cloudflare (AU dans la base)
ROCKSTAR = "185.56.65.10"


class FakeList(dict):
    def __iter__(self):
        return iter(self.items())

    def add(self, ip, name):
        self[ip] = name

    def remove(self, ip):
        self.pop(ip)

    def save(self):
        pass


class Pkt:
    def __init__(self, src, inbound=True):
        self.is_inbound = inbound
        self.is_outbound = not inbound
        self.ip = type("ip", (), {"src_addr": src, "dst_addr": "10.0.0.2"})()
        self.payload = b"x"
        self.dst_port = 6672


class W:
    def __init__(self):
        self.sent = []

    def send(self, p):
        self.sent.append(p)


def ctrl(**kw):
    clock = [1000.0]
    c = ls.LiveSessionController({}, FakeList(), clock=lambda: clock[0], **kw)
    return c, clock


# -- données embarquées --------------------------------------------------------


def test_vpn_data_bundled_and_small():
    assert vpn.db_path().exists()
    assert vpn.db_path().stat().st_size < 200_000
    assert vpn.is_vpn(FR_VPN) and vpn.is_vpn(AU_VPN)
    assert not vpn.is_vpn(US) and not vpn.is_vpn(FR)


def test_vpn_never_rockstar_and_invalid():
    assert not vpn.is_vpn(ROCKSTAR)
    for bad in ("", "x", "::1", "999.1.1.1"):
        assert vpn.is_vpn(bad) is False


def test_vpn_corrupt_file_is_safe(tmp_path, monkeypatch):
    bad = tmp_path / "v.gz"
    bad.write_bytes(gzip.compress(b"\x00\x00\x00\x05\x00\x00\x00\x01"))  # s > e
    monkeypatch.setattr(vpn, "db_path", lambda: bad)
    vpn._load.cache_clear()
    vpn.is_vpn.cache_clear()
    try:
        assert vpn.is_vpn(AU_VPN) is False
    finally:
        vpn._load.cache_clear()
        vpn.is_vpn.cache_clear()


@given(st.integers(0, 2**32 - 1))
def test_vpn_never_raises(n):
    import ipaddress

    assert isinstance(vpn.is_vpn(str(ipaddress.IPv4Address(n))), bool)


# -- réglages ------------------------------------------------------------------


def test_settings_defaults():
    s = fl.FilterSettings.from_config({})
    assert s.trusted == {"FR", "BE", "CH", "CA"}
    assert s.ping_max_ms == 150 and s.rate_pps == 60
    assert s.vpn_flag is True and s.vpn_auto_block is False


def test_settings_from_data_json():
    s = fl.FilterSettings.from_config(
        {
            "rate_limit_pps": 120,
            "ping_max_ms": 90,
            "vpn_auto_block": True,
            "trusted_countries": ["de", 3, "XXX"],
        }
    )
    assert s.rate_pps == 120 and s.ping_max_ms == 90 and s.vpn_auto_block
    assert {"FR", "BE", "CH", "CA", "DE"} == s.trusted  # défauts jamais retirés


@given(
    st.dictionaries(
        st.sampled_from(
            [
                fl.RATE_KEY,
                fl.PING_KEY,
                fl.VPN_BLOCK_KEY,
                fl.VPN_FLAG_KEY,
                fl.TRUSTED_KEY,
            ]
        ),
        st.one_of(
            st.none(),
            st.booleans(),
            st.floats(),
            st.integers(),
            st.text(max_size=3),
            st.lists(st.text(max_size=3)),
        ),
    )
)
def test_settings_fuzz(data):
    s = fl.FilterSettings.from_config(data)
    assert s.rate_pps >= 1 and 1 <= s.ping_max_ms <= 10_000
    assert {"FR", "BE", "CH", "CA"} <= s.trusted
    assert isinstance(s.vpn_auto_block, bool)


# -- pays ----------------------------------------------------------------------


def test_country_flags_only_foreign():
    f = fl.PeerFilters()
    assert f.observe(0.0, FR, True) == []
    keys = [k for k, _ in f.observe(0.0, US, True)]
    assert keys == ["live.ev.foreign"]
    assert "PAYS" in f.badges(US) and f.badges(FR) == ""


def test_country_never_blocks():
    c, _ = ctrl()
    w = W()
    pol = ls.LivePolicy()
    assert ls.handle_packet(w, Pkt(US), c.blocked, {}, 0.0, policy=pol)
    assert len(w.sent) == 1


# -- débit ---------------------------------------------------------------------


def test_rate_alert_at_60_pps():
    f = fl.PeerFilters()
    alerts = []
    for i in range(60):
        alerts += f.observe(i / 100, FR, True)
    assert [k for k, _ in alerts] == ["live.ev.rate"]
    assert alerts[0][1]["pps"] == 60


def test_rate_59_no_alert_and_window_slides():
    f = fl.PeerFilters()
    for i in range(59):
        assert f.observe(i / 59, FR, True) == []
    m = fl.RateMeter()
    for i in range(200):
        m.observe(i * 0.02, FR, 60)  # 50 pkt/s
    assert m.observe(4.0, FR, 60) <= 51


def test_rate_configurable():
    f = fl.PeerFilters(fl.FilterSettings.from_config({"rate_limit_pps": 10}))
    keys = [k for i in range(10) for k, _ in f.observe(i / 100, FR, True)]
    assert keys == ["live.ev.rate"]


# -- ping ----------------------------------------------------------------------


def test_ping_estimate_needs_samples_and_flags():
    p = fl.PingEstimator()
    ts = 0.0
    for _ in range(fl.PING_MIN_SAMPLES):
        p.observe(ts, US, True)
        p.observe(ts + 0.3, US, False)  # après silence >= PING_IDLE
        p.observe(ts + 0.5, US, True)  # réponse 200 ms plus tard
        ts += 1.0
    assert p.estimate(US) == pytest.approx(200, abs=1)
    f = fl.PeerFilters(ping=p)
    keys = [k for k, _ in f.observe(ts, FR, True)]
    assert "live.ev.ping" not in keys  # FR : pas d'échantillons


def test_ping_no_estimate_for_continuous_stream():
    p = fl.PingEstimator()
    for i in range(500):
        p.observe(i * 0.01, US, i % 2 == 0)
    assert p.estimate(US) is None


@given(
    st.lists(st.tuples(st.floats(0, 1e6, allow_nan=False), st.booleans()), max_size=200)
)
def test_ping_fuzz_bounded(events):
    p = fl.PingEstimator(max_tracked=4)
    for ts, inbound in sorted(events):
        p.observe(ts, f"203.0.113.{int(ts) % 9}", inbound)
    assert len(p.samples) <= 4 and len(p.pending) <= 4 and len(p.last_in) <= 4
    for s in p.samples.values():
        assert all(0 <= x <= fl.PING_MAX_SAMPLE * 1000 for x in s)


# -- VPN -----------------------------------------------------------------------


def test_vpn_flag_on_by_default_block_off():
    f = fl.PeerFilters()
    keys = [k for k, _ in f.observe(0.0, AU_VPN, True)]
    assert "live.ev.vpn" in keys and "VPN" in f.badges(AU_VPN)
    assert not f.wants_vpn_block(AU_VPN)


def test_vpn_flag_can_be_disabled():
    f = fl.PeerFilters(fl.FilterSettings(vpn_flag=False))
    assert "live.ev.vpn" not in [k for k, _ in f.observe(0.0, AU_VPN, True)]


def test_vpn_auto_block_guards():
    settings = fl.FilterSettings(vpn_auto_block=True)
    c, _ = ctrl(
        filters=fl.PeerFilters(settings), friends={"203.0.113.7": "a"}, auto_block=True
    )
    assert c.vpn_block(AU_VPN) is True and ls.is_blocked(c.blocked, AU_VPN, 1000.0)
    assert c.vpn_block(FR_VPN) is False  # pays de confiance
    assert c.vpn_block(ROCKSTAR) is False
    c.friends[AU_VPN] = "ami"
    c.blocked.clear()
    assert c.vpn_block(AU_VPN) is False  # ami
    assert c.auto_block is True  # réglage du bouclier inchangé


def test_r3_vpn_block_requires_auto_block():
    c, _ = ctrl(filters=fl.PeerFilters(fl.FilterSettings(vpn_auto_block=True)))
    assert c.auto_block is False
    assert c.vpn_block(AU_VPN) is False and AU_VPN not in c.blocked
    assert c.auto_block is False


def test_vpn_block_unavailable_without_ranges():
    c, _ = ctrl(auto_block_available=False)
    assert c.vpn_block(AU_VPN) is False


def test_protected_never_flagged():
    f = ls.make_filters({})
    assert f.observe(0.0, ROCKSTAR, True) == []


def test_background_filters_skip_friends():
    class Mon:
        def add_packet(self, *a):
            pass

    class Rec:
        def write(self, *a):
            pass

    class Q:
        def __init__(self, items):
            self.items = items

        def get(self, timeout=0):
            if not self.items:
                import queue

                raise queue.Empty
            return self.items.pop(0)

    c, _ = ctrl(filters=ls.make_filters({}), friends={US: "ami"})
    s = ls.BackgroundSession(
        None,
        Q([(0.0, US, 10, True, 6672), (0.0, AU_VPN, 10, True, 6672)]),
        c,
        Mon(),
        ls.PlayerCounter(),
        Rec(),
    )
    s.step()
    s.step()
    assert not any(US in e for e in c.events)
    assert any(AU_VPN in e for e in c.events)


def test_render_shows_badges():
    from network.anomaly import SessionMonitor

    mon = SessionMonitor()
    mon.add_packet(US, 100, 1000.0)
    c, _ = ctrl(filters=ls.make_filters({}))
    c.filters.observe(1000.0, US, True)
    frame = ls.render(mon, c, mon.evaluate(1000.0), "", 1000.0)
    assert "[PAYS]" in frame


# -- alertes : délais indépendants par motif, borne exacte 60 s ------------------


def test_filter_cooldown_per_reason_and_boundary():
    f = fl.PeerFilters()
    assert f._cooldown_ok(US, "pays", 0.0)
    assert f._cooldown_ok(US, "debit", 10.0)  # autre motif : indépendant
    assert not f._cooldown_ok(US, "pays", 59.9)
    assert f._cooldown_ok(US, "pays", 60.0)
    assert not f._cooldown_ok(US, "debit", 69.9)
    assert f._cooldown_ok(US, "debit", 70.0)


def test_blackbox_auto_cooldown_per_reason_and_boundary(tmp_path):
    b = bb.BlackBox(tmp_path, seconds=5, clock=lambda: 0.0)
    assert b.trigger("verrou", 0.0, auto=True)
    assert b.trigger("bouclier", 10.0, auto=True)  # motif indépendant
    assert not b.trigger("verrou", 59.9, auto=True)
    assert b.trigger("verrou", 60.0, auto=True)
    assert not b.trigger("bouclier", 69.9, auto=True)
    assert b.trigger("bouclier", 70.0, auto=True)


# -- F1 : débordement des IP vues ----------------------------------------------


def test_f1_overflow_flag_and_lock_lets_unknown_pass():
    pol = ls.LivePolicy(max_seen=2)
    for ip in ("203.0.113.1", "203.0.113.2", "203.0.113.3"):
        assert not pol.drop(True, ip)
    assert pol.seen_overflow
    pol.lock_on = True
    assert not pol.drop(True, "203.0.113.9")  # inconnue : passe (liste pleine)
    assert not pol.drop(True, "203.0.113.1")


def test_f1_lock_still_drops_without_overflow():
    pol = ls.LivePolicy(max_seen=10)
    pol.drop(True, "203.0.113.1")
    pol.lock_on = True
    assert pol.drop(True, "203.0.113.9") and not pol.seen_overflow


def test_f1_lock_refused_when_overflowed_and_alert():
    class Flag:
        value = 1

    c, _ = ctrl(overflow_flag=Flag())
    assert c.toggle_session_lock() is False and c.session_lock is False
    assert any(str(ls.MAX_SEEN) in e for e in c.events)
    head = "\n".join(ls.render_head(c, ""))
    assert t("live.lock_full", max=ls.MAX_SEEN) in head
    cfg = type("C", (), {"data": {}, "save": lambda self: None})()
    ls.handle_key("v", c, [], c.blocked, None, lambda _p: "", cfg)
    assert ls.SESSION_LOCK_KEY not in cfg.data


def test_f1_lock_off_still_toggles_when_overflowed():
    c, _ = ctrl(session_lock=True)
    c.seen_overflow_local = True
    assert c.toggle_session_lock() is True and c.session_lock is False


@given(st.lists(st.integers(0, 50), max_size=200), st.integers(1, 20))
def test_f1_fuzz_bounded(ips, cap):
    pol = ls.LivePolicy(max_seen=cap)
    for n in ips:
        pol.drop(True, f"203.0.113.{n}")
    assert len(pol.seen) <= cap
    assert pol.seen_overflow == (len(set(ips)) > cap)


# -- F2 : caractères non imprimables -------------------------------------------

EVIL = "\x1b[31mBad\x07Guy\x00\u200b"


def test_f2_add_friend_and_load_friends_strip_controls():
    c, _ = ctrl()
    assert c.add_friend("203.0.113.5", EVIL)
    assert c.friends["203.0.113.5"] == "[31mBadGuy"
    out = ls.load_friends({"203.0.113.6": EVIL, "203.0.113.7": "\x1b\x07"})
    assert out == {"203.0.113.6": "[31mBadGuy", "203.0.113.7": "203.0.113.7"}


def test_f2_offender_reason_stripped():
    e = _parse({"first": 1, "last": 2, "count": 1, "reason": "x\x1b[2Jy\r\n"})
    assert e is not None and e.reason == "x[2Jy"


@given(st.text())
def test_f2_printable_fuzz(s):
    out = ls.clean_nick(s, "ip")
    assert all(ch.isprintable() for ch in out) and len(out) <= ls.MAX_NICK


# -- F3 : recidivistes.json > 2 Mo ---------------------------------------------


def test_f3_big_offender_file_ignored(tmp_path, caplog):
    p = tmp_path / "recidivistes.json"
    entry = {"first": 1, "last": 1, "count": 1, "reason": "x" * 50}
    data = {"203.0.113.1": entry}
    blob = json.dumps(data)
    p.write_text(blob + " " * (MAX_FILE_BYTES + 1 - len(blob)))
    assert len(OffenderStore(p)) == 0
    assert "ignoré" in caplog.text
    p.write_text(blob)
    assert len(OffenderStore(p)) == 1


# -- F4 : dossier de données sans LOCALAPPDATA ---------------------------------


def test_f4_windows_fallback_appdata(tmp_path, monkeypatch):
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setattr(paths.sys, "platform", "win32")
    monkeypatch.setattr(paths.Path, "home", classmethod(lambda cls: tmp_path))
    d = paths.data_dir()
    assert d == tmp_path / "AppData" / "Local" / "Guardian" and d.is_dir()
    for bad in ("Documents", "Images", "Musique", "Vidéos", "Pictures", "Music"):
        assert bad not in d.parts


def test_f4_localappdata_used(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert paths.data_dir() == tmp_path / "Guardian"


# -- F5 : rotation et restes .tmp ----------------------------------------------


def test_f5_rotate_removes_stale_tmp_and_keeps_recent(tmp_path):
    old = time.time() - 3600
    names = [f"{bb.PREFIX}{i}.csv" for i in range(4)]
    for i, n in enumerate(names):
        (tmp_path / n).write_text("x")
        os.utime(tmp_path / n, (old + i, old + i))
    (tmp_path / ".tmp-stale.csv").write_text("x")
    os.utime(tmp_path / ".tmp-stale.csv", (old, old))
    (tmp_path / ".tmp-fresh.csv").write_text("x")  # écriture en cours possible
    (tmp_path / "notes.txt").write_text("x")
    bb.rotate(tmp_path, 2)
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(
        [names[2], names[3], ".tmp-fresh.csv", "notes.txt"]
    )


# -- lignes rouges -------------------------------------------------------------


def test_red_lines_friend_and_rockstar_pass_any_filter():
    pol = ls.LivePolicy(lock_on=True, friends={"203.0.113.50"})
    for ip in ("203.0.113.50", ROCKSTAR):
        w = W()
        assert ls.handle_packet(w, Pkt(ip), {}, {}, 0.0, policy=pol)
        assert len(w.sent) == 1


def test_keys_bar_under_100():
    assert len(t("live.keys")) < 100


# -- rejeu ---------------------------------------------------------------------


def _rows():
    with FIXTURE.open(newline="", encoding="utf-8") as f:
        return list(rp.read_rows(f))


def test_replay_fixture_flags_and_drops_nothing():
    out = []
    res = rp.replay(_rows(), emit=out.append, filters=True)
    flagged = {(k, ip) for k, ip in res.flags}
    assert ("live.ev.foreign", US) in flagged
    assert ("live.ev.foreign", "9.9.9.9") in flagged
    assert ("live.ev.vpn", AU_VPN) in flagged and ("live.ev.vpn", FR_VPN) in flagged
    assert ("live.ev.rate", "9.9.9.9") in flagged
    assert not any(ip in (FR, ROCKSTAR) for _k, ip in res.flags)
    assert not any(ip == FR_VPN and k == "live.ev.foreign" for k, ip in res.flags)
    assert res.dropped == 0
    # Une seule alerte par (IP, motif) dans la minute.
    assert len(res.flags) == len(flagged)


def test_replay_fixture_vpn_block_and_friend():
    res = rp.replay(
        _rows(),
        emit=lambda _l: None,
        filters=True,
        vpn_block=True,
        auto_block=True,
        friends={AU_VPN: "ami"},
    )
    assert res.dropped == 0  # seul VPN non-confiance = ami ; FR_VPN = confiance
    res = rp.replay(_rows(), emit=lambda _l: None, filters=True, vpn_block=True)
    assert res.dropped == 0  # bouclier auto désactivé : jamais de blocage VPN
    res = rp.replay(
        _rows(), emit=lambda _l: None, filters=True, vpn_block=True, auto_block=True
    )
    assert res.dropped_by_ip[AU_VPN] > 0 and res.dropped_by_ip[FR_VPN] == 0
    assert res.dropped_by_ip[ROCKSTAR] == 0 and res.dropped_by_ip[FR] == 0


def test_replay_default_has_no_lot3_flags():
    res = rp.replay(_rows(), emit=lambda _l: None)
    assert res.flags == [] and res.dropped == 0


def test_replay_cli_flags(capsys):
    assert rp.main([str(FIXTURE), "--filtres"]) == 0
    assert "VPN" in capsys.readouterr().out


# -- bouclier : règle absolue 80 paquets/s pendant 5 s ---------------------------

from network import anomaly as an  # noqa: E402
from network.anomaly import Level, SessionMonitor  # noqa: E402

PLAYER = "203.0.113.80"
QA = Path("/workspace/guardian-qa")


def burst(ip, pps, seconds, start=0.0):
    """Paquets réguliers couvrant exactement ``seconds`` (premier à start)."""
    n = int(round(seconds * pps, 6)) + 1
    return [(start + i / pps, ip, 200, True) for i in range(n)]


def level_after(rows, **kw):
    mon = SessionMonitor(**kw)
    for ts, ip, size, _in in rows:
        mon.add_packet(ip, size, ts)
    last = rows[-1][0]
    return {p.ip: p for p in mon.evaluate(last)}[rows[-1][1]]


def test_shield_settings_clamped():
    assert an.clamp_shield_pps(None) == 80 and an.clamp_shield_pps(5) == 20
    assert an.clamp_shield_pps(5000) == 1000 and an.clamp_shield_pps(True) == 80
    assert an.clamp_shield_seconds("x") == 5.0
    assert an.clamp_shield_pps(float("nan")) == 80


@pytest.mark.parametrize(
    ("pps", "seconds", "red"),
    [
        (79, 30, False),
        (81, 5.0, True),  # 405 paquets sur 5 s > 400
        (81, 4.8, False),  # IP observée depuis < 5 s
        (80, 30, False),  # strictement supérieur
        (90, 8, True),
        (90, 4.9, False),
        (120, 10, True),
    ],
)
def test_shield_absolute_rule_boundaries(pps, seconds, red):
    p = level_after(burst(PLAYER, pps, seconds))
    assert (p.level == Level.SUSPECT) is red
    if red:
        assert p.reason_key == "reason.rate"


def test_shield_rule_configurable():
    assert level_after(burst(PLAYER, 50, 6), shield_pps=40).level == Level.SUSPECT
    assert level_after(burst(PLAYER, 90, 6), shield_pps=100).level == Level.NORMAL
    assert level_after(burst(PLAYER, 90, 3), shield_seconds=2).level == Level.SUSPECT


def test_shield_drop_below_resets_period():
    rows = burst(PLAYER, 90, 3) + burst(PLAYER, 30, 2, start=3.1)[1:]
    rows += burst(PLAYER, 90, 3, start=5.2)
    assert level_after(rows).level == Level.NORMAL


def test_shield_silence_is_not_sustained():
    mon = SessionMonitor()
    for ts, ip, size, _ in burst(PLAYER, 90, 6):
        mon.add_packet(ip, size, ts)
    assert mon.sustained(mon.peers[PLAYER], 6.0)
    assert not mon.sustained(mon.peers[PLAYER], 7.0)  # moyenne 5 s retombée


@given(st.lists(st.floats(0, 100, allow_nan=False), max_size=400))
def test_shield_fuzz_bounded(times):
    mon = SessionMonitor(shield_pps=20)
    for ts in sorted(times):
        mon.add_packet(PLAYER, 10, ts)
    if times:
        assert len(mon.peers[PLAYER].rate_ts) <= 40
        mon.evaluate(max(times))


def _replay(rows, **kw):
    return rp.replay(sorted(rows), emit=lambda _l: None, **kw)


@pytest.mark.parametrize(
    ("pps", "seconds", "cut"),
    [
        (90, 8, True),
        (120, 10, True),
        (79, 20, False),
        (90, 4.9, False),
        (81, 5.0, True),
        (81, 4.8, False),
    ],
)
def test_replay_shield_cut(pps, seconds, cut):
    res = _replay(burst(PLAYER, pps, seconds), auto_block=True)
    assert (PLAYER in res.auto_blocked) is cut
    if cut and seconds >= 8:
        assert res.dropped_by_ip[PLAYER] > 0


def test_replay_shield_respects_auto_block_toggle():
    res = _replay(burst(PLAYER, 120, 10), auto_block=False)
    assert res.auto_blocked == [] and res.dropped == 0


@pytest.mark.parametrize("pps", [120, 200])
def test_replay_shield_never_cuts_rockstar_or_friend(pps):
    rows = burst(ROCKSTAR, pps, 10) + burst("203.0.113.9", pps, 10)
    res = _replay(rows, auto_block=True, friends={"203.0.113.9": "ami"})
    assert res.auto_blocked == [] and res.dropped == 0


def test_existing_x5_rule_red_actually_cuts():
    # Normale 20 paquets/s apprise (60 s), puis 120 paquets/s pendant 10 s ;
    # règle absolue neutralisée : le rouge de la règle x5 doit couper.
    rows = burst(PLAYER, 20, an.BASELINE_SECONDS + 1)
    rows += burst(PLAYER, 120, 10, start=an.BASELINE_SECONDS + 1.01)
    res = _replay(rows, auto_block=True, settings={"shield_pps": 1000})
    assert PLAYER in res.auto_blocked and res.dropped_by_ip[PLAYER] > 0


def test_live_session_red_cuts_in_capture():
    """Chemin LIVE : évaluation -> bouclier -> liste partagée -> capture jette."""
    c, clock = ctrl(auto_block=True)

    class Q:
        def get(self, timeout=0):
            import queue

            raise queue.Empty

    mon = SessionMonitor()
    for ts, ip, size, _ in burst(PLAYER, 90, 6, start=999.0 - 6):
        mon.add_packet(ip, size, ts)
    s = ls.BackgroundSession(None, Q(), c, mon, ls.PlayerCounter(), None)
    import time as _t

    orig = _t.time
    _t.time = lambda: 999.0
    try:
        s.evaluate()
    finally:
        _t.time = orig
    assert PLAYER in c.blocked
    w = W()
    assert not ls.handle_packet(w, Pkt(PLAYER), dict(c.blocked), {}, 999.0)
    assert w.sent == []


@pytest.mark.skipif(not (QA / "rate.csv").exists(), reason="fichiers QA absents")
def test_qa_files_replay():
    for name, cut in (
        ("rate.csv", {"198.51.100.90"}),
        ("shield.csv", {"198.51.100.90", "198.51.100.120"}),
    ):
        with (QA / name).open(newline="", encoding="utf-8") as f:
            res = rp.replay(
                list(rp.read_rows(f)), emit=lambda _l: None, auto_block=True
            )
        assert set(res.auto_blocked) == cut


# -- règle absolue : instant exact de coupure (débit d'1 s > seuil, 5 s pile) ------


def first_red(rows, **kw):
    """Horodatage de la 1re évaluation rouge (évaluée après chaque paquet)."""
    mon = SessionMonitor(**kw)
    for ts, ip, size, _in in sorted(rows):
        mon.add_packet(ip, size, ts)
        p = {q.ip: q for q in mon.evaluate(ts)}.get(PLAYER)
        if p is not None and p.level == Level.SUSPECT:
            return ts
    return None


def test_cut_81_from_first_second_at_5s():
    t = first_red(burst(PLAYER, 81, 10))
    assert t is not None and 4.9 <= t <= 5.2


def test_cut_ramp_30_to_81():
    rows = burst(PLAYER, 30, 20) + burst(PLAYER, 81, 6, start=20.0)[1:]
    t = first_red(rows)
    assert t is not None and 24.9 <= t <= 25.2


def test_cut_70_to_81_average_crosses_at_4_55s():
    # Moyenne 5 s : 81x + 70(5 - x) > 400 dès x > 4,545 s.
    rows = burst(PLAYER, 70, 20) + burst(PLAYER, 81, 10, start=20.0)[1:]
    t = first_red(rows)
    assert t is not None and 24.5 <= t <= 24.8


def test_79_stable_never_cut():
    assert first_red(burst(PLAYER, 79, 60)) is None


def test_80_stable_never_cut():
    assert first_red(burst(PLAYER, 80, 60)) is None


def test_81_for_4_8s_not_cut():
    assert first_red(burst(PLAYER, 81, 4.8)) is None


def test_small_jolts_do_not_reset():
    # 81 pkt/s avec une seconde à 76 : la moyenne 5 s reste > 80 -> coupée.
    rows = burst(PLAYER, 81, 3) + burst(PLAYER, 76, 1, start=3.0)[1:]
    rows += burst(PLAYER, 90, 4, start=4.0)[1:]
    t = first_red(rows)
    assert t is not None and t <= 5.5


def test_l1_alternating_60_200_cut_near_5s():
    rows = []
    for k in range(10):
        rows += burst(PLAYER, 60 if k % 2 == 0 else 200, 0.999, start=float(k))
    t = first_red(rows)
    assert t is not None and 4.9 <= t <= 5.2


def test_short_burst_then_silence_never_cut():
    # 2 s à 250 pkt/s (500 paquets > 400) puis silence : 2 tranches occupées sur 5.
    rows = burst(PLAYER, 250, 2) + [(20.0, PLAYER, 100, True)]
    mon = SessionMonitor()
    for ts, ip, size, _ in rows:
        mon.add_packet(ip, size, ts)
    assert first_red(rows) is None
    assert not any(mon.sustained(mon.peers[PLAYER], t / 10) for t in range(0, 200))


def test_alert_shows_real_rate_not_capped():
    mon = SessionMonitor()
    for ts, ip, size, _ in burst(PLAYER, 400, 6):
        mon.add_packet(ip, size, ts)
    p = {q.ip: q for q in mon.evaluate(6.0)}[PLAYER]
    assert p.level == Level.SUSPECT and "400" in p.alert


def test_rate_memory_bounded():
    mon = SessionMonitor()
    for i in range(100_000):
        mon.add_packet(PLAYER, 10, i / 100_000)
    assert len(mon.peers[PLAYER].rate_ts) == mon.rate_cap


EARLY = Path(__file__).parent / "fixtures" / "early_lot3.csv"
EARLY10 = Path(__file__).parent / "fixtures" / "early10.csv"
T0 = 1767225600


def _cut_times(path):
    lines = []
    with path.open(newline="", encoding="utf-8") as f:
        rp.replay(list(rp.read_rows(f)), emit=lines.append, auto_block=True)
    out = {}
    for ln in lines:
        if "Bouclier auto" in ln:
            ip = ln.split(": ", 1)[1].split()[0]
            out.setdefault(ip, float(ln[1 : ln.index("]")]) - T0)
    return out


def test_replay_early10():
    cut = _cut_times(EARLY10)
    assert 4.9 <= cut["198.51.100.81"] <= 5.2
    assert 24.9 <= cut["198.51.100.5"] <= 25.2
    assert 24.5 <= cut["198.51.100.6"] <= 24.8  # 70->81 : moyenne > 80 à +4,55 s


def test_replay_early_lot3():
    cut = _cut_times(EARLY)
    assert 24.5 <= cut["198.51.100.6"] <= 25.2
    assert 24.9 <= cut["198.51.100.5"] <= 25.2


def test_replay_early_fixture_respects_toggle():
    with EARLY10.open(newline="", encoding="utf-8") as f:
        res = rp.replay(list(rp.read_rows(f)), emit=lambda _l: None)
    assert res.auto_blocked == [] and res.dropped == 0


# -- audit 6d94eb9 : plafond fixe, saturation, 75 %, inondation, tranches ---------


def st(rate, t0, t1):
    if rate == 0:
        return []
    return [t0 + k / rate for k in range(int(round((t1 - t0) * rate)))]


def rep(seq, n=6):
    out, t = [], 0.0
    for _ in range(n):
        for r, d in seq:
            out += st(r, t, t + d)
            t += d
    return out


def adv_cut(pkts, pps=80, sec=5.0, step=0.01):
    """Même harnais que /tmp/adv3.py : évaluation toutes les 10 ms."""
    m = SessionMonitor(pps, sec)
    pkts = sorted(pkts)
    i, t = 0, pkts[0]
    while t <= pkts[-1] + 0.5:
        while i < len(pkts) and pkts[i] <= t + 1e-9:
            m.add_packet(PLAYER, 200, pkts[i])
            i += 1
        p = m.peers.get(PLAYER)
        if p and m.sustained(p, t):
            return t
        t = round(t + step, 4)
    return None


ADV = [
    ("L1 60/200", lambda: rep([(60, 1), (200, 1)]), 4.9, 5.2),
    ("2s@250 puis silence", lambda: st(250, 0, 2), None, None),
    ("79 stable", lambda: st(79, 0, 20), None, None),
    ("80 stable", lambda: st(80, 0, 20), None, None),
    ("81 pendant 4,8 s", lambda: st(81, 0, 4.8), None, None),
    ("105 stable", lambda: st(105, 0, 20), 4.9, 5.1),
    ("3s@300/2s@39", lambda: rep([(300, 3), (39, 2)]), 4.9, 5.2),
    ("41/150", lambda: rep([(41, 1), (150, 1)]), 4.9, 5.3),
    ("39/200", lambda: rep([(39, 1), (200, 1)]), 4.9, 5.3),
    ("2s@39/3s@400", lambda: rep([(39, 2), (400, 3)]), 4.5, 5.0),
    ("2s silence/3s@1000", lambda: rep([(0, 2), (1000, 3)]), 3.0, 3.4),
    ("1.5s@39/1.5s@250", lambda: rep([(39, 1.5), (250, 1.5)]), 5.4, 5.8),
    ("1.2s@30/0.8s@800", lambda: rep([(30, 1.2), (800, 0.8)], 10), 3.6, 4.0),
    ("inondation 1500", lambda: st(1500, 0, 8), 0.7, 0.9),
    ("inondation 5000", lambda: st(5000, 0, 8), 0.0, 1.0),
    ("inondation 10000", lambda: st(10000, 0, 8), 0.0, 1.0),
    ("F3 2s@1000 + 3s@39", lambda: st(1000, 0, 2) + st(39, 2, 5), 1.1, 1.3),
    ("ralenti puis 81", lambda: [0.0] + st(81, 10, 20), 14.8, 15.1),
    ("ralenti puis 300", lambda: [0.0] + st(300, 10, 20), 13.1, 13.3),
    ("20 puis 300", lambda: st(20, 0, 10) + st(300, 10, 20), 13.0, 13.3),
    ("79 puis 300", lambda: st(79, 0, 10) + st(300, 10, 20), 10.0, 10.1),
    ("trou 2 s / 3 s@300", lambda: rep([(0, 2), (300, 3)], 8), 7.1, 7.3),
    ("2.1s@39 / 2.9s@1000", lambda: rep([(39, 2.1), (1000, 2.9)], 8), 3.1, 3.4),
]


@pytest.mark.parametrize(("label", "make", "lo", "hi"), ADV, ids=[a[0] for a in ADV])
def test_adv3_scenarios(label, make, lo, hi):
    t = adv_cut(make())
    if lo is None:
        assert t is None, label
    else:
        assert t is not None and lo <= t <= hi, (label, t)


@pytest.mark.parametrize("sec", [1, 1.4, 2, 2.5, 3])
def test_short_shield_seconds_uses_three_slices(sec):
    mon = SessionMonitor(80, sec)
    assert mon.slices == 3
    t = adv_cut(st(105, 0, 20), sec=sec)
    assert t is not None and sec - 1e-6 <= t <= max(sec, 1.6)


def test_slices_ceil():
    assert SessionMonitor(80, 5.2).slices == 6
    assert SessionMonitor(80, 60).slices == 60


def test_cap_fixed_8192():
    mon = SessionMonitor()
    assert mon.rate_cap == an.RATE_CAP == 8192
    for i in range(20_000):
        mon.add_packet(PLAYER, 10, i / 20_000)
    assert len(mon.peers[PLAYER].rate_ts) == 8192


def test_saturation_needs_one_second():
    mon = SessionMonitor(shield_pps=1000)  # F3 hors d'atteinte : 15000 paquets
    for i in range(9000):
        mon.add_packet(PLAYER, 10, i / 10_000)  # 10000 paquets/s pendant 0,9 s
    peer = mon.peers[PLAYER]
    assert not mon.sustained(peer, 0.9)  # saturé mais IP vue depuis < 1 s
    for i in range(9000, 11000):
        mon.add_packet(PLAYER, 10, i / 10_000)
    assert mon.sustained(peer, 1.1)
    assert not mon.sustained(peer, 2.5)  # dernier paquet il y a > 1 s


def test_peak_2s_below_cap_not_cut():
    # 2 s à 3000 paquets/s (6000 < 8192, < 3 x 400... F3 = 1200 dépassé) : F3 coupe ;
    # sans F3 (seuil élevé), le plafond n'est pas saturé : pas de coupure.
    rows = st(3000, 0, 2)
    assert adv_cut(rows, pps=1000) is None


FLOOD = Path(__file__).parent / "fixtures" / "flood.csv.gz"


def test_replay_flood_5000_cut(tmp_path):
    import gzip

    plain = tmp_path / "flood.csv"
    plain.write_bytes(gzip.decompress(FLOOD.read_bytes()))
    cut = _cut_times(plain)
    assert cut["198.51.100.50"] <= 1.0  # 5000 paquets/s pendant 8 s


def test_saturated_storage_bounded_r1():
    mon = SessionMonitor()
    worst = 0
    for i in range(60_000):
        mon.add_packet(PLAYER, 10, i / 20_000)
        worst = max(worst, len(mon.peers[PLAYER].rate_ts._ts))
    assert len(mon.peers[PLAYER].rate_ts) == an.RATE_CAP
    assert worst <= an.RATE_CAP + an.COMPACT_AT


def test_storage_compacts_on_slow_long_session_r1():
    mon = SessionMonitor()
    for i in range(20_000):
        mon.add_packet(PLAYER, 10, i / 50)  # 50 paquets/s pendant 400 s
    assert len(mon.peers[PLAYER].rate_ts._ts) <= 250 + an.COMPACT_AT
