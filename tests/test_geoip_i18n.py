"""Géolocalisation hors ligne et traductions FR/EN."""

import pytest
from guardian.util import geoip, i18n


@pytest.mark.parametrize(
    ("ip", "cc"),
    [("8.8.8.8", "US"), ("90.84.1.1", "FR"), ("81.2.69.142", "GB")],
)
def test_known_ips(ip, cc):
    assert geoip.country_code(ip) == cc
    assert geoip.country_label(ip) == f"{geoip.flag(cc)} {cc}"


@pytest.mark.parametrize(
    "ip", ["192.168.1.10", "10.0.0.1", "127.0.0.1", "0.0.0.0", "not-an-ip", "::1"]
)
def test_unknown_ips(ip):
    assert geoip.country_code(ip) is None
    assert geoip.country_label(ip) == "—"


def test_flag():
    assert geoip.flag("FR") == "\U0001f1eb\U0001f1f7"


def test_every_key_has_both_languages():
    for key, entry in i18n.STRINGS.items():
        assert set(entry) == set(i18n.LANGUAGES), key


def test_switch_language():
    try:
        assert i18n.get_language() == "fr"  # défaut
        assert i18n.t("menu.quit") == "Quitter"
        i18n.set_language("en", persist=False)
        assert i18n.t("menu.quit") == "Quit"
        assert (
            i18n.t("live.ev.unblocked", ip="203.0.113.34")
            == "IP 203.0.113.34 unblocked"
        )
        assert i18n.t("cle.inconnue") == "cle.inconnue"
        with pytest.raises(ValueError):
            i18n.set_language("de", persist=False)
    finally:
        i18n.set_language("fr", persist=False)


def test_set_language_persists():
    from config.configdata import ConfigData

    try:
        i18n.set_language("en")
        assert ConfigData().data["language"] == "en"
    finally:
        i18n.set_language("fr")


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"not gzip at all",
        None,  # gzip tronqué
        "bad_record",  # gzip valide, enregistrement incomplet
        "bad_ascii",  # code pays non ASCII
    ],
)
def test_corrupt_db_degrades(tmp_path, monkeypatch, content):
    import gzip
    import struct

    good = gzip.compress(struct.pack(">I2s", 0, b"FR") * 4)
    if content is None:
        content = good[: len(good) // 2]
    elif content == "bad_record":
        content = gzip.compress(b"\x00\x00\x00\x00FR\x01")
    elif content == "bad_ascii":
        content = gzip.compress(struct.pack(">I2s", 0, b"\xff\xfe"))
    path = tmp_path / "geo.bin.gz"
    path.write_bytes(content)
    monkeypatch.setattr(geoip, "db_path", lambda: path)
    geoip._load.cache_clear()
    geoip.country_code.cache_clear()
    try:
        assert geoip.country_label("8.8.8.8") == "—"
    finally:
        geoip._load.cache_clear()
        geoip.country_code.cache_clear()
