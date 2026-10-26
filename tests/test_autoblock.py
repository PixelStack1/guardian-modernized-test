"""Bouclier auto persistant (auto_block.json) : 7 jours, fichier séparé, garde-fous."""

import json

import pytest
from guardian.menu import livesession as ls
from guardian.network import autoblock
from guardian.network.anomaly import Level, PeerState

DAY = 86400.0


class FakeList(dict):
    def __iter__(self):
        return iter(self.items())

    def add(self, ip, name):
        self[ip] = name

    def remove(self, ip):
        del self[ip]

    def save(self):
        self.saved = True


class SyncStore:
    """Comme AutoBlockSaver, mais écrit tout de suite (tests déterministes)."""

    def __init__(self, path):
        self.path = path

    def request(self, entries):
        autoblock.save(entries, self.path)


def red(ip):
    return PeerState(ip, 0, 0, level=Level.SUSPECT)


def make(tmp_path, now, guard=None, available=True, blacklist=None):
    path = tmp_path / "auto_block.json"
    clock = [now]
    entries = autoblock.load(now, guard, path)
    ctrl = ls.LiveSessionController(
        {},
        blacklist if blacklist is not None else FakeList(),
        auto_block=True,
        clock=lambda: clock[0],
        auto_block_guard=guard,
        auto_block_available=available,
        auto_store=SyncStore(path),
        auto_entries=entries,
    )
    return ctrl, path, clock


def on_disk(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_duration_is_seven_days():
    assert ls.AUTO_BLOCK_SECONDS == 7 * 24 * 3600


def test_persists_across_restart_and_not_in_blacklist(tmp_path):
    bl = FakeList()
    ctrl, path, _ = make(tmp_path, 1000.0, blacklist=bl)
    assert ctrl.auto_block_if_needed(red("203.0.113.5"))
    assert on_disk(path) == {"203.0.113.5": 1000.0 + ls.AUTO_BLOCK_SECONDS}
    assert "203.0.113.5" not in bl  # jamais dans data.json
    # « redémarrage » 3 jours plus tard
    ctrl2, _, _ = make(tmp_path, 1000.0 + 3 * DAY)
    assert ctrl2.blocked["203.0.113.5"] == 1000.0 + ls.AUTO_BLOCK_SECONDS
    assert ls.is_blocked(ctrl2.blocked, "203.0.113.5", 1000.0 + 3 * DAY)
    assert "BLOQU" in ctrl2.block_status("203.0.113.5")


def test_expiry_unblocks_and_purges_file(tmp_path):
    ctrl, path, clock = make(tmp_path, 1000.0)
    ctrl.auto_block_if_needed(red("203.0.113.5"))
    clock[0] += ls.AUTO_BLOCK_SECONDS - 1
    ctrl.expire()
    assert "203.0.113.5" in ctrl.blocked
    clock[0] += 1
    ctrl.expire()
    assert "203.0.113.5" not in ctrl.blocked
    assert on_disk(path) == {}
    assert any("expir" in e for e in ctrl.events)


def test_load_purges_expired(tmp_path):
    path = tmp_path / "auto_block.json"
    path.write_text(json.dumps({"203.0.113.1": 500.0, "203.0.113.2": 5000.0}))
    assert autoblock.load(1000.0, path=path) == {"203.0.113.2": 5000.0}


def test_key_d_removes_from_file(tmp_path):
    bl = FakeList()
    ctrl, path, _ = make(tmp_path, 1000.0, blacklist=bl)
    ctrl.auto_block_if_needed(red("203.0.113.5"))
    ctrl.unblock("203.0.113.5")
    assert "203.0.113.5" not in ctrl.blocked and on_disk(path) == {}
    assert not getattr(bl, "saved", False)  # data.json non touché
    ctrl2, _, _ = make(tmp_path, 2000.0)
    assert "203.0.113.5" not in ctrl2.blocked


def test_manual_block_moves_auto_entry_to_blacklist(tmp_path):
    bl = FakeList()
    ctrl, path, _ = make(tmp_path, 1000.0, blacklist=bl)
    ctrl.auto_block_if_needed(red("203.0.113.5"))
    ctrl.block("203.0.113.5")
    assert ctrl.blocked["203.0.113.5"] == ls.PERMANENT
    assert "203.0.113.5" in bl and on_disk(path) == {}


@pytest.mark.parametrize(
    "content",
    [
        "{pas du json",
        "",
        "[1, 2]",
        '"texte"',
        "\x00\xff",
        json.dumps({"pas-une-ip": 9e9, "203.0.113.1": "demain", "203.0.113.2": True}),
        json.dumps({"203.0.113.3": float("nan")}).replace("NaN", "NaN"),
        json.dumps({"203.0.113.4": None, "999.1.1.1": 9e9, "203.0.113.5": -1}),
    ],
)
def test_corrupt_or_invalid_file_is_ignored(tmp_path, content):
    path = tmp_path / "auto_block.json"
    path.write_text(content, encoding="utf-8", errors="ignore")
    assert autoblock.load(1000.0, path=path) == {}
    ctrl, _, _ = make(tmp_path, 1000.0)
    assert ctrl.blocked == {}


def test_valid_entries_kept_next_to_invalid(tmp_path):
    path = tmp_path / "auto_block.json"
    path.write_text(json.dumps({"x": 1, "203.0.113.7": 9e9, "2001:db8::1": 9e9}))
    assert autoblock.load(1000.0, path=path) == {"203.0.113.7": 9e9, "2001:db8::1": 9e9}


def test_unreadable_file_is_ignored(tmp_path):
    (tmp_path / "auto_block.json").mkdir()  # un dossier à la place du fichier
    assert autoblock.load(1000.0, path=tmp_path / "auto_block.json") == {}


def test_entry_cap(tmp_path):
    path = tmp_path / "auto_block.json"
    data = {f"10.0.{i // 256}.{i % 256}": 2000.0 + i for i in range(30)}
    path.write_text(json.dumps(data))
    out = autoblock.load(1000.0, path=path, limit=10)
    assert len(out) == 10 and min(out.values()) == 2020.0  # les plus récents gardés
    assert len(autoblock.cap(data, 5)) == 5


def test_controller_caps_entries(tmp_path, monkeypatch):
    import network.autoblock as live_autoblock  # module tel qu'importé par livesession

    monkeypatch.setattr(live_autoblock, "MAX_ENTRIES", 3)
    ctrl, path, clock = make(tmp_path, 1000.0)
    for i in range(5):
        clock[0] += 1
        ctrl.auto_block_if_needed(red(f"203.0.113.{i}"))
    assert len(ctrl.auto_entries) == 3 and len(on_disk(path)) == 3
    assert "203.0.113.0" not in ctrl.blocked


def test_guards_filter_on_load(tmp_path):
    path = tmp_path / "auto_block.json"
    path.write_text(
        json.dumps({"203.0.113.1": 9e9, "185.56.65.7": 9e9, "20.1.2.3": 9e9})
    )
    from guardian.util.network import construct_cidr_block_set

    guard = ls.make_auto_block_guard(
        {"203.0.113.1"}, construct_cidr_block_set({"20.0.0.0/8"})
    )
    ctrl, _, _ = make(tmp_path, 1000.0, guard=guard)
    assert ctrl.blocked == {}  # whitelist, Rockstar, Azure : jamais appliqués
    assert autoblock.load(1000.0, guard, path) == {}


def test_guards_on_new_block(tmp_path):
    ctrl, path, _ = make(tmp_path, 1000.0, guard=lambda ip: ip == "203.0.113.1")
    assert not ctrl.auto_block_if_needed(red("203.0.113.1"))
    assert not path.exists() or on_disk(path) == {}


def test_off_by_default_and_without_ranges(tmp_path):
    assert ls.AUTO_BLOCK_DEFAULT is False
    path = tmp_path / "auto_block.json"
    path.write_text(json.dumps({"203.0.113.1": 9e9}))
    ctrl, _, _ = make(tmp_path, 1000.0, available=False)
    assert not ctrl.auto_block and ctrl.blocked == {}  # entrées non appliquées
    assert not ctrl.auto_block_if_needed(red("203.0.113.2"))
    assert on_disk(path) == {"203.0.113.1": 9e9}  # fichier laissé intact


def test_atomic_write_and_tmp_cleanup(tmp_path, monkeypatch):
    path = tmp_path / "auto_block.json"
    assert autoblock.save({"203.0.113.1": 9e9}, path)
    assert on_disk(path) == {"203.0.113.1": 9e9}

    def fail(*_a):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(autoblock.os, "replace", fail)
    assert autoblock.save({"203.0.113.2": 9e9}, path) is False
    assert on_disk(path) == {"203.0.113.1": 9e9}  # ancien contenu intact
    assert not list(tmp_path.glob("*.tmp"))


def test_save_into_impossible_dir_does_not_raise(tmp_path):
    blocker = tmp_path / "fichier"
    blocker.write_text("x")
    assert autoblock.save({"203.0.113.1": 9e9}, blocker / "auto_block.json") is False


def test_background_saver(tmp_path):
    path = tmp_path / "auto_block.json"
    saver = autoblock.AutoBlockSaver(path)
    for i in range(50):
        saver.request({f"203.0.113.{i}": 9e9})
    saver.close()
    assert on_disk(path) == {"203.0.113.49": 9e9}  # dernier état gagnant
    assert 1 <= saver.saves <= 50 and not saver._thread.is_alive()


def test_store_path_uses_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert autoblock.store_path() == tmp_path / "Guardian" / "auto_block.json"


def test_no_store_means_memory_only(tmp_path):
    ctrl = ls.LiveSessionController({}, FakeList(), auto_block=True)
    assert ctrl.auto_block_if_needed(red("203.0.113.1"))
    assert not list(tmp_path.iterdir())
