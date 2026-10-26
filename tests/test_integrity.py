from pathlib import Path

import pytest
from guardian.util import integrity as integ

DLL = "WinDivert64.dll"
SYS = "WinDivert64.sys"


def _fake_dir(tmp_path: Path, dll: bytes, sys_: bytes, monkeypatch) -> Path:
    (tmp_path / DLL).write_bytes(dll)
    (tmp_path / SYS).write_bytes(sys_)
    import hashlib

    monkeypatch.setattr(
        integ,
        "OFFICIAL_WINDIVERT_SHA256",
        {
            DLL: hashlib.sha256(b"dll").hexdigest(),
            SYS: hashlib.sha256(b"sys").hexdigest(),
        },
    )
    return tmp_path


def test_official_hashes_are_full_sha256():
    assert set(integ.OFFICIAL_WINDIVERT_SHA256) == {DLL, SYS}
    for h in integ.OFFICIAL_WINDIVERT_SHA256.values():
        assert len(h) == 64 and int(h, 16) >= 0


def test_verify_ok(tmp_path, monkeypatch):
    d = _fake_dir(tmp_path, b"dll", b"sys", monkeypatch)
    assert set(integ.verify_windivert(d)) == {DLL, SYS}


@pytest.mark.parametrize("dll,sys_", [(b"evil", b"sys"), (b"dll", b"evil")])
def test_verify_mismatch_refuses(tmp_path, monkeypatch, dll, sys_):
    d = _fake_dir(tmp_path, dll, sys_, monkeypatch)
    with pytest.raises(integ.IntegrityError, match="does not match"):
        integ.verify_windivert(d)


def test_verify_missing_refuses(tmp_path, monkeypatch):
    d = _fake_dir(tmp_path, b"dll", b"sys", monkeypatch)
    (d / SYS).unlink()
    with pytest.raises(integ.IntegrityError, match="missing"):
        integ.verify_windivert(d)


def test_windivert_dir_is_absolute_package_dir_not_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    d = integ.windivert_dir()
    assert d.is_absolute() and d.name == "windivert_dll" and d != tmp_path


def test_pin_dll_path_absolute(tmp_path):
    import pydivert.windivert_dll as wd

    old = wd.DLL_PATH
    try:
        dll = integ.pin_windivert_dll_path(tmp_path)
        assert str(tmp_path.resolve() / DLL) == wd.DLL_PATH and dll.is_absolute()
    finally:
        wd.DLL_PATH = old


def test_installed_binaries_match_official_if_present():
    d = integ.windivert_dir()
    if not (d / DLL).exists():
        pytest.skip("pydivert installed without Windows binaries (non-Windows wheel)")
    integ.verify_windivert(d)
