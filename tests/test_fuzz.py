"""Hypothesis fuzzing: CIDR and RIPE/Azure parsing must never crash with an unexpected exception."""

import contextlib
import json

from guardian.util import dynamicblacklist as db
from guardian.util import network as net
from hypothesis import given, settings
from hypothesis import strategies as st

json_values = st.recursive(
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False)
    | st.text(max_size=30),
    lambda c: st.lists(c, max_size=5)
    | st.dictionaries(st.text(max_size=10), c, max_size=5),
    max_leaves=25,
)


@settings(max_examples=500)
@given(st.text(max_size=40))
def test_cidr_to_tuple_only_valueerror(s):
    try:
        ip, prefix = net.cidr_to_tuple(s)
    except ValueError:
        return
    assert 0 <= ip < 2**32 and 8 <= prefix <= 32


@settings(max_examples=300)
@given(st.lists(st.text(max_size=25), max_size=20))
def test_construct_cidr_block_set_never_raises(items):
    out = net.construct_cidr_block_set(items)
    assert all(8 <= p <= 32 for _, p in out)


@settings(max_examples=300)
@given(st.integers(0, 2**32 - 1), st.integers(0, 32))
def test_cidr_roundtrip(ip, prefix):
    s = f"{net.ipaddress.IPv4Address(ip)}/{prefix}"
    if prefix < 8:
        try:
            net.cidr_to_tuple(s)
        except ValueError:
            return
        raise AssertionError("broad prefix accepted")
    base, p = net.cidr_to_tuple(s)
    assert p == prefix and base == ip & ((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF)


@settings(max_examples=400)
@given(json_values)
def test_ripe_parser_only_valueerror(value):
    for body in (
        json.dumps(value).encode(),
        json.dumps({"data": {"prefixes": value}}).encode(),
    ):
        with contextlib.suppress(ValueError):
            db.parse_ripe_prefixes(body)


@settings(max_examples=200)
@given(st.binary(max_size=200))
def test_ripe_parser_random_bytes(body):
    with contextlib.suppress(ValueError):
        db.parse_ripe_prefixes(body)


@settings(max_examples=400)
@given(json_values)
def test_azure_parser_only_valueerror(value):
    bodies = [
        json.dumps(value).encode(),
        json.dumps({"values": value}).encode(),
        json.dumps(
            {
                "values": [
                    {"name": "AzureCloud", "properties": {"addressPrefixes": value}}
                ]
            }
        ).encode(),
    ]
    for body in bodies:
        with contextlib.suppress(ValueError):
            db.parse_azure_ip_ranges(body)


@settings(max_examples=200)
@given(st.binary(max_size=200))
def test_azure_parser_random_bytes(body):
    with contextlib.suppress(ValueError):
        db.parse_azure_ip_ranges(body)


@settings(max_examples=200, deadline=None)
@given(st.sets(st.text(max_size=20), max_size=10))
def test_accept_list_never_raises(tmp_path_factory, items):
    d = tmp_path_factory.mktemp("c")
    out = db.accept_list("f", items, {"203.0.113.0/26"}, d)
    assert out == items or out == {"203.0.113.0/26"}
