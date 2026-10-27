"""Mode rejeu / simulation (QA, Linux ou Windows) : ``python -m guardian.replay <csv>``.

Rejoue un enregistrement de la vue en direct (CSV ``horodatage,ip,taille,sens``,
format de network/recorder.py) dans la MÊME logique que la session en direct :
classification serveur Rockstar / joueur, alerte nouveau joueur, détection
d'anomalies, bouclier auto (optionnel) et décision de rejet par paquet
(``should_drop``). N'ouvre AUCUN handle WinDivert, n'envoie ni ne fabrique aucun
paquet, ne fait aucun appel réseau : seules les décisions sont affichées.
Par défaut rien n'est écrit sur le disque (journal : option ``--journal``).
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

# Les modules de Guardian s'importent sans préfixe (« from menu... ») : comme
# guardian/__main__.py, on ajoute leur dossier au chemin.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from menu import livesession as ls  # noqa: E402
from network.anomaly import SessionMonitor  # noqa: E402
from network.newplayer import NewPlayerTracker, PlayerJournal  # noqa: E402
from network.recorder import HEADER  # noqa: E402
from network.relay import RELAY_ALLOW, RELAY_VALUES, is_block, normalize  # noqa: E402
from util.i18n import LANGUAGES, set_language, t  # noqa: E402

Row = tuple[float, str, int, bool]


def read_rows(lines: TextIO) -> Iterator[Row]:
    """Lignes valides du CSV (en-tête obligatoire). Les lignes invalides sont ignorées."""
    reader = csv.reader(lines)
    header = next(reader, None)
    if header is None or tuple(h.strip() for h in header) != HEADER:
        raise ValueError(f"en-tête attendu : {','.join(HEADER)}")
    for row in reader:
        if len(row) != 4:
            continue
        try:
            ts, ip, size, sens = float(row[0]), row[1].strip(), int(row[2]), row[3]
        except ValueError:
            continue
        sens = sens.strip().lower()
        if not ip or sens not in ("entrant", "sortant") or size < 0:
            continue
        yield ts, ip, size, sens == "entrant"


class _MemoryBlacklist:
    """Blacklist en mémoire (le rejeu ne touche jamais data.json)."""

    def __init__(self) -> None:
        self.items: dict[str, str] = {}

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter(list(self.items.items()))

    def __contains__(self, ip: object) -> bool:
        return ip in self.items

    def add(self, ip: str, name: str) -> None:
        self.items[ip] = name

    def remove(self, ip: str) -> None:
        self.items.pop(ip, None)

    def save(self) -> None:
        pass


@dataclass
class ReplayResult:
    packets: int = 0
    dropped: int = 0
    new_players: list[str] = field(default_factory=list)
    servers: set[str] = field(default_factory=set)
    dropped_by_ip: Counter[str] = field(default_factory=Counter)
    events: list[str] = field(default_factory=list)


def replay(
    rows: Iterator[Row] | Sequence[Row],
    relay_mode: str = RELAY_ALLOW,
    auto_block: bool = False,
    journal: PlayerJournal | None = None,
    emit: Callable[[str], Any] = print,
) -> ReplayResult:
    """Rejoue ``rows`` ; ``emit`` reçoit chaque ligne de décision."""
    relay_block = is_block(relay_mode)
    now_box = [0.0]

    def clock() -> float:
        return now_box[0]

    blocked: dict[str, float] = {}
    ctrl = ls.LiveSessionController(
        blocked,
        _MemoryBlacklist(),
        auto_block=auto_block,
        clock=clock,
        # Plages Rockstar/Take-Two statiques uniquement (aucun appel réseau).
        auto_block_guard=ls.is_rockstar_server,
        relay_mode=relay_mode,
    )
    monitor = SessionMonitor()
    tracker = NewPlayerTracker(
        ls.is_rockstar_server,
        journal,
        alert=lambda ip, cc: t("live.ev.new_player", ip=ip, country=cc),
    )
    res = ReplayResult()
    next_eval: float | None = None
    n_events = 0

    def flush_events() -> None:
        nonlocal n_events
        for ev in ctrl.events[n_events:]:
            res.events.append(ev)
            emit(f"[{now_box[0]:.3f}] {ev}")
        n_events = len(ctrl.events)

    for ts, ip, size, inbound in rows:
        now_box[0] = ts
        res.packets += 1
        if ls.is_rockstar_server(ip):
            res.servers.add(ip)
        alert = tracker.observe(ts, ip, inbound)
        if alert:
            res.new_players.append(ip)
            ctrl.events.append(alert)
        if inbound:
            monitor.add_packet(ip, size, ts)
        if next_eval is None or ts >= next_eval:
            next_eval = ts + ls.EVAL_SECONDS
            ctrl.expire()
            for peer in monitor.evaluate(ts):
                ctrl.auto_block_if_needed(peer)
            monitor.prune(ts)
        flush_events()
        drop = ls.should_drop(
            inbound,
            ip,
            ip,
            blocked,
            ctrl.total_blocked,
            ts,
            ctrl.total_block,
            relay_block,
        )
        if drop:
            if res.dropped_by_ip[ip] == 0:
                emit(
                    f"[{ts:.3f}] "
                    + t("replay.drop", ip=ip, dir="entrant" if inbound else "sortant")
                )
            res.dropped += 1
            res.dropped_by_ip[ip] += 1
    emit(
        t(
            "replay.summary",
            packets=res.packets,
            dropped=res.dropped,
            players=len(res.new_players),
            servers=len(res.servers),
        )
    )
    return res


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m guardian.replay",
        description="Rejoue un enregistrement CSV (horodatage,ip,taille,sens) sans WinDivert.",
    )
    parser.add_argument("csv", type=Path)
    parser.add_argument("--relais", choices=RELAY_VALUES, default=RELAY_ALLOW)
    parser.add_argument(
        "--bouclier", action="store_true", help="active le bouclier auto"
    )
    parser.add_argument("--lang", choices=LANGUAGES, default="fr")
    parser.add_argument(
        "--journal", type=Path, help="dossier où écrire joueurs.log (sinon : rien)"
    )
    args = parser.parse_args(argv)
    set_language(args.lang, persist=False)
    journal = PlayerJournal(args.journal) if args.journal else None
    try:
        with args.csv.open(newline="", encoding="utf-8") as f:
            replay(read_rows(f), normalize(args.relais), args.bouclier, journal)
    except (OSError, ValueError) as e:
        print(f"erreur : {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
