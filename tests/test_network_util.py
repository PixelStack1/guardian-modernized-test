import json
from unittest import mock

import pytest
import requests
from guardian.util import dynamicblacklist as db
from guardian.util import network as net
from guardian.util.network import (
    calculate_ip_to_int,
    cidr_to_tuple,
    construct_cidr_block_set,
    ip_in_cidr_block_set,
)


def test_ip_to_int():
    assert calculate_ip_to_int("1.2.3.4") == 0x01020304


def test_cidr():
    assert cidr_to_tuple("185.56.64.0/22") == (calculate_ip_to_int("185.56.64.0"), 22)
    blocks = construct_cidr_block_set(["185.56.64.0/22", "garbage", "10.0.0.0/8"])
    assert ip_in_cidr_block_set("185.56.67.255", blocks)
    assert not ip_in_cidr_block_set("185.56.68.0", blocks)
    assert ip_in_cidr_block_set("10.200.1.1", blocks)


def _resp(payload, headers=None):
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    r = mock.MagicMock()
    r.__enter__.return_value = r
    r.headers = headers or {}
    r.iter_content.return_value = [
        body[i : i + 1000] for i in range(0, len(body), 1000)
    ]
    r.raise_for_status.return_value = None
    return r


def test_ripe_parsing_ignores_extra_fields_and_ipv6():
    payload = {
        "pipeline": "1478200",  # field that broke prsw (issue #163)
        "data": {"prefixes": [{"prefix": "185.56.64.0/22"}, {"prefix": "2a00::/32"}]},
    }
    with mock.patch.object(db.requests, "get", return_value=_resp(payload)) as g:
        assert db.get_announced_prefixes(202021, {"x"}) == {"185.56.64.0/22"}
    assert g.call_args.kwargs["timeout"]


def test_ripe_fallback_on_error():
    with mock.patch.object(db.requests, "get", side_effect=requests.ConnectionError):
        assert db.get_announced_prefixes(1, {"1.1.1.0/24"}) == {"1.1.1.0/24"}
    with mock.patch.object(db.requests, "get", return_value=_resp({"bad": 1})):
        assert db.get_announced_prefixes(1, {"1.1.1.0/24"}) == {"1.1.1.0/24"}


def test_import_has_no_network_side_effect():
    # module was already imported above without network: prsw call at import time is gone
    assert not hasattr(db, "ripe")


def test_parse_azure():
    content = b'{"changeNumber": 1, "values": [{"name": "AzureCloud", "properties": {"addressPrefixes": ["20.0.0.0/8"]}}]}'
    assert db.parse_azure_ip_ranges(content) == ["20.0.0.0/8"]
    stamped = db.azure_file_add_timestamp(content, "u")
    assert b"acquiredFrom" in stamped


@pytest.mark.parametrize(
    "bad",
    [
        "0.0.0.0/0",
        "1.2.3/24",
        "999.1.1.1/8",
        "10.0.0.0/7",
        "x/8",
        "2a00::/32",
        "1.2.3.4",
    ],
)
def test_cidr_rejects_invalid(bad):
    if bad == "1.2.3.4":
        # bare IPv4 is a valid /32
        assert cidr_to_tuple(bad) == (calculate_ip_to_int(bad), 32)
        return
    with pytest.raises(ValueError):
        cidr_to_tuple(bad)
    assert construct_cidr_block_set([bad]) == set()


def test_cidr_masks_host_bits():
    assert cidr_to_tuple("185.56.65.7/22") == (calculate_ip_to_int("185.56.64.0"), 22)


def test_capped_rejects_large_content_length():
    r = _resp(b"x", headers={"Content-Length": str(db.MAX_RIPE_BYTES + 1)})
    with (
        mock.patch.object(db.requests, "get", return_value=r),
        pytest.raises(db.ResponseTooLarge),
    ):
        db.get_capped("u", db.MAX_RIPE_BYTES)


def test_capped_rejects_large_stream():
    r = _resp(b"x" * 3000)
    with (
        mock.patch.object(db.requests, "get", return_value=r) as g,
        pytest.raises(db.ResponseTooLarge),
    ):
        db.get_capped("u", 2500, timeout=1)
    assert g.call_args.kwargs["stream"] is True


def test_ripe_oversized_falls_back():
    r = _resp(b"x", headers={"Content-Length": str(10**9)})
    with mock.patch.object(db.requests, "get", return_value=r):
        assert db.get_announced_prefixes(1, {"1.1.1.0/24"}) == {"1.1.1.0/24"}


def _ipify(text):
    r = mock.Mock()
    r.raise_for_status.return_value = None
    r.raw.read.return_value = text
    return r


def test_public_ip_valid():
    with mock.patch.object(net.requests, "get", return_value=_ipify(b" 203.0.113.5\n")):
        assert net.get_public_ip() == "203.0.113.5"


@pytest.mark.parametrize("text", [b"<html>", b"999.1.1.1", b""])
def test_public_ip_invalid_returns_none(text):
    with mock.patch.object(net.requests, "get", return_value=_ipify(text)):
        assert net.get_public_ip() is None


def test_public_ip_network_error_returns_none():
    with mock.patch.object(net.requests, "get", side_effect=requests.ConnectionError):
        assert net.get_public_ip() is None


def test_azure_scrape_no_links_raises():
    with (
        mock.patch.object(
            db.requests, "get", return_value=_resp(b"<html>nothing</html>")
        ),
        pytest.raises(db.ScrapeError),
    ):
        db.get_azure_ip_ranges_download("u")


def test_data_file_uses_localappdata(tmp_path, monkeypatch):
    from guardian.util import paths

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "lad"))
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    (cwd / "data.json").write_text("{}")
    monkeypatch.chdir(cwd)
    p = paths.data_file("data.json")
    assert p == tmp_path / "lad" / "Guardian" / "data.json"
    assert p.read_text() == "{}"  # legacy file migrated
