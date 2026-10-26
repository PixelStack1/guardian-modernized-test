"""Real WinDivert test on a Windows CI runner (admin). Pure network: no game, no process access."""

import json
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, "guardian")
import pydivert  # noqa: E402

from network import sessions as s  # noqa: E402

PORTS = [6672, 61455, 61456, 61457, 61458]
results: dict = {"pydivert": getattr(pydivert, "__version__", "?")}


def sc_query() -> str:
    r = subprocess.run(["sc", "query", "WinDivert"], capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


def sniff(filt: str, send_fn, expect: int, timeout: float = 5.0):
    got = []
    with pydivert.WinDivert(filt, flags=pydivert.Flag.SNIFF) as w:

        def loop():
            try:
                for p in w:
                    got.append(p)
                    if len(got) >= expect:
                        break
            except Exception as e:  # handle closed
                got.append(e)

        t = threading.Thread(target=loop, daemon=True)
        t.start()
        time.sleep(0.5)
        send_fn()
        t.join(timeout)
    return [p for p in got if not isinstance(p, Exception)]


def udp_send(addr: str, port: int, size: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as so:
        so.sendto(b"\x01" * size, (addr, port))


results["sc_before"] = sc_query()

# 1. Capture per port, loopback (WinDivert sees loopback as outbound + loopback flag)
for addr, label in [("127.0.0.1", "loopback"), ("192.0.2.1", "outbound_testnet")]:
    for port in PORTS:
        pk = sniff(
            f"udp.DstPort == {port} and ip.DstAddr == {addr}",
            lambda a=addr, p=port: udp_send(a, p, 300),
            1,
        )
        ok = bool(pk) and pk[0].dst_port == port and len(pk[0].payload) == 300
        results[f"capture_{label}_{port}"] = {
            "ok": ok,
            "n": len(pk),
            "outbound": pk[0].is_outbound if pk else None,
            "loopback": getattr(pk[0], "is_loopback", None) if pk else None,
        }

results["sc_after_open"] = sc_query()

# 2. Guardian filter logic on packets really captured
pk = sniff(
    "udp.DstPort == 6672 and ip.DstAddr == 127.0.0.1",
    lambda: [udp_send("127.0.0.1", 6672, n) for n in (12, 300, 191, 3)],
    4,
)
conn = type("C", (), {"send": lambda self, x: None})()
wl = s.WhitelistSession(set(), 1, conn)
wl_friend = s.WhitelistSession({"127.0.0.1"}, 1, conn)
solo = s.SoloSession(1, conn)
locked = s.LockedSession(1, conn)
results["filter_on_captured"] = [
    {
        "size": len(p.payload),
        "whitelist_stranger": wl.is_packet_allowed(p),
        "whitelist_friend": wl_friend.is_packet_allowed(p),
        "solo": solo.is_packet_allowed(p),
        "locked": locked.is_packet_allowed(p),
    }
    for p in pk
]
exp = {
    12: (True, True, True, True),
    300: (False, True, False, True),
    191: (False, True, False, False),
    3: (False, True, False, True),
}
results["filter_ok"] = len(pk) == 4 and all(
    (r["whitelist_stranger"], r["whitelist_friend"], r["solo"], r["locked"])
    == exp[r["size"]]
    for r in results["filter_on_captured"]
)

# 3. Real drop/reinject (non-sniff) with SoloSession logic on loopback 6672
recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
recv.bind(("127.0.0.1", 6672))
recv.settimeout(1.0)
stop = threading.Event()
with pydivert.WinDivert(
    "udp.DstPort == 6672 and ip.DstAddr == 127.0.0.1", priority=5
) as w:

    def filt():
        try:
            for p in w:
                if solo.is_packet_allowed(p):
                    w.send(p)
                if stop.is_set():
                    break
        except Exception:
            pass

    t = threading.Thread(target=filt, daemon=True)
    t.start()
    time.sleep(0.5)
    for n in (300, 12, 191, 18):
        udp_send("127.0.0.1", 6672, n)
    received = []
    try:
        while True:
            received.append(len(recv.recv(2048)))
    except OSError:
        pass
    stop.set()
recv.close()
results["drop_reinject_received_sizes"] = sorted(received)
results["drop_reinject_ok"] = sorted(received) == [12, 18]

time.sleep(2)
results["sc_after_close"] = sc_query()

# 4. Guardian DriverLifecycle with the real driver: stop it first, let Guardian load it, then clean up.
from util.driver import DriverLifecycle  # noqa: E402

subprocess.run(["sc", "stop", "WinDivert"], capture_output=True)
time.sleep(3)
results["lifecycle_sc_before"] = sc_query()
lc = DriverLifecycle(pydivert.WinDivert)
lc.start()
with pydivert.WinDivert(
    "udp.DstPort == 6672 and ip.DstAddr == 127.0.0.1", flags=pydivert.Flag.SNIFF
):
    results["lifecycle_sc_loaded"] = sc_query()
lc.cleanup()
time.sleep(3)
results["lifecycle_loaded_by_guardian"] = lc.loaded_by_guardian
results["lifecycle_sc_after_cleanup"] = sc_query()
results["lifecycle_ok"] = (
    lc.loaded_by_guardian and "RUNNING" not in results["lifecycle_sc_after_cleanup"]
)
print(json.dumps(results, indent=2))
ok = (
    all(v["ok"] for k, v in results.items() if k.startswith("capture_"))
    and results["filter_ok"]
    and results["drop_reinject_ok"]
    and results["lifecycle_ok"]
)
sys.exit(0 if ok else 1)
