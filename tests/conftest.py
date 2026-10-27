import ctypes
import os
import struct
import sys
import tempfile
from unittest import mock

import pydivert
import pytest

# Never write user data (data.json, caches, logs) outside a temp dir during tests.
os.environ["LOCALAPPDATA"] = tempfile.mkdtemp(prefix="guardian-tests-")

# Guardian is Windows-only; on other OSes stub the Win32 console APIs so modules import.
if sys.platform != "win32" and not hasattr(ctypes, "WinDLL"):
    ctypes.WinDLL = mock.MagicMock()  # type: ignore[attr-defined]


def make_udp_packet(
    src: str = "203.0.113.10",
    dst: str = "192.168.1.2",
    payload: bytes = b"",
    sport: int = 6672,
    dport: int = 6672,
    inbound: bool = True,
) -> pydivert.Packet:
    """Build a real IPv4/UDP pydivert.Packet from raw bytes (no driver needed)."""
    udp_len = 8 + len(payload)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + udp_len,
        0,
        0,
        64,
        17,
        0,
        bytes(int(o) for o in src.split(".")),
        bytes(int(o) for o in dst.split(".")),
    )
    udp_hdr = struct.pack("!HHHH", sport, dport, udp_len, 0)
    direction = pydivert.Direction.INBOUND if inbound else pydivert.Direction.OUTBOUND
    return pydivert.Packet(ip_hdr + udp_hdr + payload, (1, 0), direction)


@pytest.fixture
def packet_factory():
    return make_udp_packet
