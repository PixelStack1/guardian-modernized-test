"""Faux pydivert MINIMAL pour lancer les tests sur Linux sans la dépendance réelle.

Chargé par tests/conftest.py UNIQUEMENT si ``import pydivert`` échoue. Il ne parle à
aucun pilote : il ne fait que décoder des octets IPv4/UDP/TCP construits par les tests
(mêmes attributs que pydivert.Packet utilisés par Guardian). WinDivert lève toujours.
"""

from __future__ import annotations

import enum
import socket
import struct
from types import SimpleNamespace
from typing import Any

FAKE = True


class Direction(enum.IntEnum):
    OUTBOUND = 0
    INBOUND = 1


class Flag(enum.IntFlag):
    DEFAULT = 0
    SNIFF = 1
    DROP = 2


class Packet:
    def __init__(self, raw: bytes, interface: Any = (0, 0), direction: Any = 0):
        self.raw = memoryview(bytes(raw))
        self.interface = interface
        self.direction = Direction(int(direction))
        data = bytes(raw)
        ihl = (data[0] & 0x0F) * 4
        proto = data[9]
        self.ip = SimpleNamespace(
            src_addr=socket.inet_ntoa(data[12:16]),
            dst_addr=socket.inet_ntoa(data[16:20]),
        )
        self.udp: Any = None
        self.tcp: Any = None
        sport, dport = struct.unpack("!HH", data[ihl : ihl + 4])
        if proto == 17:
            self.udp = SimpleNamespace(src_port=sport, dst_port=dport)
            body = ihl + 8
        elif proto == 6:
            self.tcp = SimpleNamespace(src_port=sport, dst_port=dport)
            body = ihl + ((data[ihl + 12] >> 4) * 4)
        else:
            sport = dport = 0
            body = ihl
        self.src_port: int | None = sport
        self.dst_port: int | None = dport
        self.payload = data[body:]

    @property
    def is_inbound(self) -> bool:
        return self.direction == Direction.INBOUND

    @property
    def is_outbound(self) -> bool:
        return self.direction == Direction.OUTBOUND

    @property
    def src_addr(self) -> str:
        return str(self.ip.src_addr)

    @property
    def dst_addr(self) -> str:
        return str(self.ip.dst_addr)

    @property
    def payload_length(self) -> int:
        return len(self.payload)


class WinDivert:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise OSError("WinDivert indisponible (faux pydivert de test)")
