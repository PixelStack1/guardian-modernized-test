"""Badge VPN/hébergeur, hors ligne (aucun appel réseau).

Données : plages des AS d'hébergeurs/VPN connus extraites de sapics/ip-location-db
« origin-asn » (PDDL-1.0), régénérer avec tools/build_vpn.py. Liste INDICATIVE :
un VPN inconnu n'est pas détecté et un joueur sur un serveur loué est signalé.
"""

from __future__ import annotations

import bisect
import gzip
import ipaddress
import struct
import sys
import zlib
from functools import lru_cache
from pathlib import Path

DB_NAME = "vpn_ipv4.bin.gz"


def db_path() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "util" / DB_NAME
    return Path(__file__).resolve().parent / DB_NAME


@lru_cache(maxsize=1)
def _load() -> tuple[list[int], list[int]]:
    # Fichier absent ou corrompu : aucune IP signalée, jamais de plantage.
    try:
        raw = gzip.decompress(db_path().read_bytes())
        starts: list[int] = []
        ends: list[int] = []
        for start, end in struct.iter_unpack(">II", raw):
            starts.append(start)
            ends.append(end)
    except (OSError, EOFError, struct.error, zlib.error):
        return [], []
    if starts != sorted(starts) or any(
        s > e for s, e in zip(starts, ends, strict=True)
    ):
        return [], []
    return starts, ends


@lru_cache(maxsize=4096)
def is_vpn(ip: str) -> bool:
    """Vrai si l'IP est dans une plage VPN/hébergeur connue. Ne lève jamais."""
    try:
        n = int(ipaddress.IPv4Address(ip))
    except ValueError:
        return False
    starts, ends = _load()
    i = bisect.bisect_right(starts, n) - 1
    return i >= 0 and n <= ends[i]
