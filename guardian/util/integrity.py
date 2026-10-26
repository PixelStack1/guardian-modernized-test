"""Integrity and absolute-path loading of the bundled WinDivert binaries.

Expected hashes are those of the official basil00 WinDivert v2.2.2-A release
(https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip,
zip SHA256 63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15):
x64/WinDivert.dll (shipped by pydivert as WinDivert64.dll) and x64/WinDivert64.sys.
The pydivert 4.0.1 wheel files were verified byte-identical to that release.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
from pathlib import Path

OFFICIAL_WINDIVERT_SHA256 = {
    "WinDivert64.dll": "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2",
    "WinDivert64.sys": "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2",
}


class IntegrityError(Exception):
    """A WinDivert binary is missing or does not match the official hash."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def windivert_dir() -> Path:
    """Absolute directory of pydivert's bundled binaries (package dir / PyInstaller bundle), never the CWD."""
    spec = importlib.util.find_spec("pydivert.windivert_dll")
    if spec is None or spec.origin is None:
        raise IntegrityError("pydivert.windivert_dll not found")
    return Path(spec.origin).resolve().parent


def verify_windivert(directory: Path | None = None) -> dict[str, str]:
    directory = (directory or windivert_dir()).resolve()
    found: dict[str, str] = {}
    for name, expected in OFFICIAL_WINDIVERT_SHA256.items():
        path = directory / name
        if not path.is_file():
            raise IntegrityError(f"{path} is missing")
        actual = sha256_file(path)
        if actual != expected:
            raise IntegrityError(
                f"{path} SHA256 {actual} does not match official WinDivert 2.2.2-A {expected}"
            )
        found[name] = actual
    return found


def pin_windivert_dll_path(directory: Path | None = None) -> Path:
    """Force pydivert to load the DLL by absolute path and remove the CWD from the DLL search order."""
    directory = (directory or windivert_dir()).resolve()
    dll = directory / "WinDivert64.dll"
    import pydivert.windivert_dll as windivert_dll  # type: ignore[import-untyped]  # does not load the DLL (lazy proxies)

    windivert_dll.DLL_PATH = str(dll)
    if sys.platform == "win32":  # pragma: no cover - Windows only
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.SetDllDirectoryW(
            ""
        )  # removes the current directory from the search path
        LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
        LOAD_LIBRARY_SEARCH_USER_DIRS = 0x00000400
        LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200
        kernel32.SetDefaultDllDirectories(
            LOAD_LIBRARY_SEARCH_SYSTEM32
            | LOAD_LIBRARY_SEARCH_USER_DIRS
            | LOAD_LIBRARY_SEARCH_APPLICATION_DIR
        )
        os.add_dll_directory(str(directory))
    return dll


def secure_windivert() -> dict[str, str]:
    """Verify hashes then pin the absolute DLL path. Raises IntegrityError on any mismatch."""
    directory = windivert_dir()
    hashes = verify_windivert(directory)
    pin_windivert_dll_path(directory)
    return hashes
