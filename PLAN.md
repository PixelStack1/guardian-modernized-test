# Guardian modernisation plan (local branch `modernize`, not published)

Scope: pure network firewall (WinDivert on UDP/6672). Nothing reads, modifies or injects into the GTA V process/memory.

1. Python target: 3.12 / 3.13 (`>=3.12,<3.14`). CI workflow on 3.13.
2. Dependencies:
   - Drop `prsw` (RIPEstat wrapper, broken by RIPEstat API adding a `pipeline` field -> upstream issue #163 "Guardian 3.5 refuses to launch"). Replace with a direct, timeout-bound `requests` call to `stat.ripe.net/data/announced-prefixes`, lazy (not at import time) with static fallback on *any* error.
   - pydivert 2.1.0 (2017, WinDivert 1.3) -> pydivert 4.x (WinDivert 2.2, py3.10-3.14). API used by Guardian (WinDivert(filter, priority=, flags=), Flag.SNIFF, Packet.payload/raw/ip/src_addr/is_inbound, w.send) is unchanged. MUST be validated on Windows.
   - pyinstaller 5 -> 6, requests/questionary/tqdm to current.
   - Dev: black+isort+flake8 -> ruff (lint+format), mypy, pytest.
3. Fixes:
   - Whitelist filter crashed (IndexError) on payloads < 5 bytes (`payload[4]`), killing the filter process.
   - `raw[28:30]` assumed 20-byte IPv4 header; use `payload[0:2]` (same bytes, robust to IP options).
   - `PipeConnection` import only exists on Windows -> guard under TYPE_CHECKING so modules import/analyze elsewhere.
   - Network calls without timeouts (ipify, Azure) -> add timeouts.
   - build.py Windows-only path separators -> os.path; CI: upload-artifact v3 (deprecated) -> v4, release step only on tags.
4. Tests: unit tests for packet-filter decisions (Solo/Whitelist/Blacklist/Locked) with real pydivert Packet objects built from raw IPv4/UDP bytes (no driver), CIDR helpers, RIPE fallback (mocked), IPCollector counting.
5. Static analysis: ruff, mypy --platform win32 --strict, compileall, import smoke test.
6. Package: zip of source without .git/.venv/caches.
