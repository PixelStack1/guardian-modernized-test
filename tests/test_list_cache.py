import json

from guardian.util import dynamicblacklist as db

BASE = {f"10.{i}.0.0/16" for i in range(20)}


def test_first_valid_list_accepted_and_cached(tmp_path):
    assert db.accept_list("t", BASE, {"203.0.113.0/26"}, tmp_path) == BASE
    assert db.load_cached_list("t", tmp_path) == BASE


def test_empty_rejected_keeps_old(tmp_path):
    db.accept_list("t", BASE, set(), tmp_path)
    assert db.accept_list("t", set(), set(), tmp_path) == BASE


def test_malformed_rejected_keeps_old(tmp_path):
    db.accept_list("t", BASE, set(), tmp_path)
    assert db.accept_list("t", BASE | {"999.1.1.1/8"}, set(), tmp_path) == BASE
    assert db.accept_list("t", BASE | {"0.0.0.0/0"}, set(), tmp_path) == BASE


def test_change_over_30_percent_rejected(tmp_path):
    db.accept_list("t", BASE, set(), tmp_path)
    changed = set(list(sorted(BASE))[:13]) | {
        f"11.{i}.0.0/16" for i in range(7)
    }  # 14/20 = 70%
    assert db.accept_list("t", changed, set(), tmp_path) == BASE
    assert db.load_cached_list("t", tmp_path) == BASE


def test_change_under_30_percent_accepted(tmp_path):
    db.accept_list("t", BASE, set(), tmp_path)
    changed = (BASE - {"10.0.0.0/16"}) | {"203.0.113.192/27"}  # 2/20 = 10%
    assert db.accept_list("t", changed, set(), tmp_path) == changed


def test_no_cache_failure_uses_fallback(tmp_path):
    assert db.accept_list("t", None, {"203.0.113.0/26"}, tmp_path) == {"203.0.113.0/26"}


def test_corrupt_cache_ignored(tmp_path):
    (tmp_path / "cache_t.json").write_text("{not json")
    assert db.accept_list("t", None, {"203.0.113.0/26"}, tmp_path) == {"203.0.113.0/26"}


def test_ripe_rejected_keeps_cached(tmp_path, monkeypatch):
    db.accept_list("ripe_AS1", BASE, set(), tmp_path)
    body = json.dumps({"data": {"prefixes": [{"prefix": "203.0.113.128/26"}]}}).encode()
    monkeypatch.setattr(db, "get_capped", lambda *a, **k: body)
    assert db.get_announced_prefixes(1, {"203.0.113.64/26"}, cache_dir=tmp_path) == BASE


def test_azure_change_over_30_percent_keeps_backup(tmp_path, monkeypatch):
    def azure(prefixes):
        return json.dumps(
            {
                "values": [
                    {"name": "AzureCloud", "properties": {"addressPrefixes": prefixes}}
                ]
            }
        ).encode()

    backup = tmp_path / "db.json"
    backup.write_bytes(azure(sorted(BASE)))
    monkeypatch.setattr(
        db, "get_azure_ip_ranges_download", lambda: ("u", azure(["203.0.113.224/27"]))
    )
    monkeypatch.setattr(db, "get_t2_ranges", lambda: set())
    result = db.get_dynamic_blacklist(str(backup))
    assert len(result) == len(BASE)
    assert json.loads(backup.read_bytes())["values"][0]["properties"][
        "addressPrefixes"
    ] == sorted(BASE)


def _big_change():
    return {f"11.{i}.0.0/16" for i in range(20)}


def test_big_change_accepted_after_7_days(tmp_path):
    db.accept_list("t", BASE, set(), tmp_path, now=1000.0)
    assert (
        db.accept_list("t", _big_change(), set(), tmp_path, now=1000.0 + 6 * 86400)
        == BASE
    )
    assert (
        db.accept_list("t", _big_change(), set(), tmp_path, now=1000.0 + 8 * 86400)
        == _big_change()
    )


def test_big_change_accepted_after_3_rejections(tmp_path):
    db.accept_list("t", BASE, set(), tmp_path, now=1000.0)
    for _ in range(3):
        assert db.accept_list("t", _big_change(), set(), tmp_path, now=1001.0) == BASE
    assert (
        db.accept_list("t", _big_change(), set(), tmp_path, now=1001.0) == _big_change()
    )
    # counter reset after acceptance
    assert json.loads((tmp_path / "cache_t.json").read_text())["rejections"] == 0


def test_rejection_counter_resets_on_valid_list(tmp_path):
    db.accept_list("t", BASE, set(), tmp_path, now=1000.0)
    db.accept_list("t", _big_change(), set(), tmp_path, now=1001.0)
    small = (BASE - {"10.0.0.0/16"}) | {"203.0.113.192/27"}
    assert db.accept_list("t", small, set(), tmp_path, now=1002.0) == small
    assert json.loads((tmp_path / "cache_t.json").read_text())["rejections"] == 0


def test_malformed_never_accepted_even_when_stale(tmp_path):
    db.accept_list("t", BASE, set(), tmp_path, now=1000.0)
    for _ in range(5):
        assert (
            db.accept_list("t", {"0.0.0.0/0"}, set(), tmp_path, now=1000.0 + 30 * 86400)
            == BASE
        )
    assert db.accept_list("t", set(), set(), tmp_path, now=1000.0 + 30 * 86400) == BASE
