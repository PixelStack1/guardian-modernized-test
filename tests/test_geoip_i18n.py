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
        assert i18n.t("live.ev.unblocked", ip="1.2.3.4") == "IP 1.2.3.4 unblocked"
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
