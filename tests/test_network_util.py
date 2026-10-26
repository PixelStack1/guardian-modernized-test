from unittest import mock

import requests
from guardian.util import dynamicblacklist as db
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


def _resp(payload):
    r = mock.Mock()
    r.json.return_value = payload
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
