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
    c, _ = ctrl(filters=fl.PeerFilters(settings), friends={"203.0.113.7": "a"})
    assert c.vpn_block(AU_VPN) is True and ls.is_blocked(c.blocked, AU_VPN, 1000.0)
    assert c.vpn_block(FR_VPN) is False  # pays de confiance
    assert c.vpn_block(ROCKSTAR) is False
    c.friends[AU_VPN] = "ami"
    c.blocked.clear()
    assert c.vpn_block(AU_VPN) is False  # ami
    assert c.auto_block is False  # réglage du bouclier inchangé


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
        friends={AU_VPN: "ami"},
    )
    assert res.dropped == 0  # seul VPN non-confiance = ami ; FR_VPN = confiance
    res = rp.replay(_rows(), emit=lambda _l: None, filters=True, vpn_block=True)
    assert res.dropped_by_ip[AU_VPN] > 0 and res.dropped_by_ip[FR_VPN] == 0
    assert res.dropped_by_ip[ROCKSTAR] == 0 and res.dropped_by_ip[FR] == 0


def test_replay_default_has_no_lot3_flags():
    res = rp.replay(_rows(), emit=lambda _l: None)
    assert res.flags == [] and res.dropped == 0


def test_replay_cli_flags(capsys):
    assert rp.main([str(FIXTURE), "--filtres"]) == 0
    assert "VPN" in capsys.readouterr().out
