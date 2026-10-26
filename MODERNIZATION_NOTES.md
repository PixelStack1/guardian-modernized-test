# Modernisation notes (local, unpublished) — 2026-10-26

Base: upstream main @ 63d751b (2025-01-27). Licence: LGPL-3.0 (unchanged; this derivative stays LGPL-3.0).
Hard limit respected: pure WinDivert network filter on inbound UDP/6672. No access to the GTA V process or memory.

## Changes
- Python >=3.12,<3.14 (CI: 3.12 + 3.13 lint/test on Ubuntu, build on 3.13 Windows).
- pydivert 2.1.0 (WinDivert 1.3) -> ^4.0.1 (WinDivert 2.2). Same API surface used by Guardian.
- prsw removed (cause of upstream issue #163 "Guardian 3.5 refuses to launch": `TypeError: Output.__init__() got an unexpected keyword argument 'pipeline'` at import). Replaced by direct RIPEstat call, lazy, 10 s timeout, static fallback on any error.
- FIX: `network/sessioninfo.py` crashed at import on any Python (`multiprocessing.Queue[...]` annotation evaluated at runtime -> `'method' object is not subscriptable`). Added `from __future__ import annotations`.
- FIX: WhitelistSession IndexError on UDP payloads < 5 bytes (killed the filter process). Heuristic extracted to `is_whitelist_service_packet()` (pure, tested); uses payload[0:2] instead of raw[28:30].
- FIX: T2/R* ranges now also added when the Azure download fails and the backup file is used.
- Timeouts on all HTTP requests; `PipeConnection` imports under TYPE_CHECKING; build.py portable path; CI actions updated, GitHub release step only on tags.
- Tooling: black/isort/flake8 -> ruff; mypy strict (win32) passes; 41 pytest tests.

## Must be tested on a real Windows PC (see report)
