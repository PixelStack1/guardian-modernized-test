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

## Security audit fixes (2026-10-26)
1. Driver: unload only if loaded by Guardian (DriverLifecycle), finally + atexit; README `sc stop WinDivert` note.
2. CIDR: ipaddress.IPv4Network(strict=False), prefixlen < 8 rejected, ValueError/IndexError caught; tests 0.0.0.0/0, 1.2.3/24, 999.1.1.1/8.
3. Streamed size caps (Azure 10 MB, RIPE 1 MB, MS page 2 MB); get_public_ip -> IPv4Address-validated or None (safe at menu import); `if not re_files`.
4. Workflows: `permissions: contents: read`; no auto-commit/push; `ruff format --check`. No release job exists.
5. Actions pinned by SHA; UPX dropped (`--noupx`, ghaction-upx removed); softprops release step already removed.
6. urllib3 2.8.0, certifi 2026.10.23, idna 3.20, setuptools 84.2.1, virtualenv 21.14.13, filelock 4.2.4; pytest 9.1.1 (PYSEC-2026-1845); poetry pinned 2.5.1 in CI.
7. Duplicate `if:` in build.yml removed.
8. Data/logs in %LOCALAPPDATA%\Guardian; data.json/db.json/logs git-ignored (were not tracked).

## Hardening A-G + extra ports (2026-10-26)
A. CI: dist/SHA256SUMS + actions/attest-build-provenance (job-scoped id-token/attestations write, continue-on-error, outcome logged).
B. util/integrity.py: SHA256 of WinDivert64.dll/.sys vs official 2.2.2-A (zip sha256 63cb4176…3f15, verified byte-identical to pydivert 4.0.1 wheel); exit 3 on mismatch.
C. DLL_PATH pinned to absolute package dir; SetDllDirectoryW("") + SetDefaultDllDirectories; data/logs/crash reports in %LOCALAPPDATA%\Guardian (fallback CWD).
D. accept_list(): cache_<name>.json, rejects empty/malformed/>30% change; Azure db.json not overwritten on rejection.
E. PACKET_FILTER = UDP 6672 + 61455-61458 exactly; open_windivert()/probe_filter() -> FilterOpenError -> clean exit 4.
F. .github/dependabot.yml (pip + github-actions).
G. tests/test_fuzz.py (hypothesis).
