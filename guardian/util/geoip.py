"""Géolocalisation IPv4 -> pays, hors ligne (aucun appel réseau).

Données : sapics/ip-location-db « geo-whois-asn-country » (CC0-1.0, domaine public),
https://github.com/sapics/ip-location-db — régénérer avec tools/build_geoip.py.
"""

from __future__ import annotations

import bisect
import gzip
import ipaddress
import struct
import sys
from functools import lru_cache
from pathlib import Path

DB_NAME = "geoip_ipv4.bin.gz"
UNKNOWN = "—"


def db_path() -> Path:
    # Exe PyInstaller : fichier ajouté sous util/ dans le dossier temporaire.
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "util" / DB_NAME
    return Path(__file__).resolve().parent / DB_NAME


@lru_cache(maxsize=1)
def _load() -> tuple[list[int], list[str]]:
    try:
        raw = gzip.decompress(db_path().read_bytes())
    except OSError:
        return [], []
    starts: list[int] = []
    codes: list[str] = []
    for start, cc in struct.iter_unpack(">I2s", raw):
        starts.append(start)
        codes.append(cc.decode("ascii"))
    return starts, codes


@lru_cache(maxsize=4096)
def country_code(ip: str) -> str | None:
    """Code ISO à 2 lettres, ou None (privée, réservée, inconnue, invalide)."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    if not addr.is_global:
        return None
    starts, codes = _load()
    i = bisect.bisect_right(starts, int(addr)) - 1
    if i < 0:
        return None
    cc = codes[i]
    return cc if cc.isalpha() and cc.isupper() else None


def flag(cc: str) -> str:
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc)


def country_label(ip: str) -> str:
    """« 🇫🇷 FR », ou « — » si inconnu."""
    cc = country_code(ip)
    return f"{flag(cc)} {cc}" if cc else UNKNOWN
