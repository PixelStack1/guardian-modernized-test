"""Génère guardian/util/vpn_ipv4.bin.gz : plages IPv4 d'hébergeurs/VPN connus.

Source : sapics/ip-location-db « origin-asn » (PDDL-1.0, domaine public, sans
attribution obligatoire), https://github.com/sapics/ip-location-db
Usage : python tools/build_vpn.py origin-asn-ipv4-num.csv

On ne garde QUE les plages des AS listés dans VPN_ASNS (hébergeurs, clouds et
fournisseurs VPN connus). Microsoft/Azure (AS8075) est volontairement EXCLU
(infrastructure Rockstar dynamique) ; Rockstar/Take-Two (AS202021, AS46555)
ne sont jamais inclus.

Format : gzip de N enregistrements (début uint32 BE, fin uint32 BE) triés,
plages contiguës fusionnées.
"""

import csv
import gzip
import struct
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "guardian" / "util" / "vpn_ipv4.bin.gz"

VPN_ASNS = {
    16276,  # OVH
    24940,  # Hetzner
    14061,  # DigitalOcean
    20473,  # Choopa / Vultr
    63949,  # Linode / Akamai cloud
    16509,
    14618,  # Amazon AWS
    396982,  # Google Cloud
    31898,  # Oracle Cloud
    60068,
    212238,  # Datacamp / CDN77 (nombreux VPN grand public)
    9009,  # M247 (nombreux VPN grand public)
    51167,  # Contabo
    60781,
    28753,  # Leaseweb
    136787,
    147049,  # Tefincom / PacketHub (NordVPN)
    39351,  # 31173 Services (Mullvad)
    62240,  # Clouvider
    8100,  # QuadraNet
    53667,  # FranTech / BuyVM
    202425,  # IP Volume
    45102,
    37963,  # Alibaba Cloud
    132203,  # Tencent Cloud
    13335,  # Cloudflare (WARP)
}
NEVER = {202021, 46555, 8075}
assert not VPN_ASNS & NEVER


def main(src: str) -> None:
    ranges: list[tuple[int, int]] = []
    with open(src, newline="", encoding="utf-8") as f:
        for row in csv.reader(f):
            try:
                start, end, asn = int(row[0]), int(row[1]), int(row[2])
            except (ValueError, IndexError):
                continue
            if asn in VPN_ASNS:
                ranges.append((start, end))
    ranges.sort()
    merged: list[tuple[int, int]] = []
    for s, e in ranges:
        if merged and s <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    data = b"".join(struct.pack(">II", s, e) for s, e in merged)
    OUT.write_bytes(gzip.compress(data, 9, mtime=0))
    print(f"{len(merged)} plages, {OUT.stat().st_size} octets -> {OUT}")


if __name__ == "__main__":
    main(sys.argv[1])
