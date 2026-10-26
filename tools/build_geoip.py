"""Génère guardian/util/geoip_ipv4.bin.gz à partir du CSV CC0 de sapics/ip-location-db.

Source : https://github.com/sapics/ip-location-db (geo-whois-asn-country, IPv4, CC0-1.0)
Usage : python tools/build_geoip.py geo-whois-asn-country-ipv4-num.csv

Format : gzip de N enregistrements (début uint32 big-endian, code pays 2 octets ASCII),
triés ; « -- » = plage inconnue. Les plages contiguës du même pays sont fusionnées.
"""

import csv
import gzip
import struct
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "guardian" / "util" / "geoip_ipv4.bin.gz"


def main(src: str) -> None:
    records: list[tuple[int, str]] = []
    end_prev = -1
    with open(src, newline="") as f:
        for start_s, end_s, cc in csv.reader(f):
            start, end, cc = int(start_s), int(end_s), cc.upper()[:2]
            if start > end_prev + 1:
                records.append((end_prev + 1, "--"))
            if not records or records[-1][1] != cc:
                records.append((start, cc))
            end_prev = end
    if end_prev < 2**32 - 1:
        records.append((end_prev + 1, "--"))
    data = b"".join(struct.pack(">I2s", s, c.encode()) for s, c in records)
    OUT.write_bytes(gzip.compress(data, 9, mtime=0))
    print(f"{len(records)} plages, {OUT.stat().st_size} octets -> {OUT}")


if __name__ == "__main__":
    main(sys.argv[1])
