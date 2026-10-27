"""Mode rejeu / simulation (QA, Linux ou Windows) : ``python -m guardian.replay <csv>``.

Rejoue un enregistrement de la vue en direct (CSV ``horodatage,ip,taille,sens``,
format de network/recorder.py) dans la MÊME logique que la session en direct :
classification serveur Rockstar / joueur, alerte nouveau joueur, détection
d'anomalies, bouclier auto (optionnel) et décision de rejet par paquet
(``should_drop``), plus le lot 2 : verrou de session (``--verrou``) et
récidivistes (``--recidiviste``, ``--sans-coupure``) via ``LivePolicy``. N'ouvre AUCUN handle WinDivert, n'envoie ni ne fabrique aucun
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
from network.offenders import OffenderStore  # noqa: E402
from network.recorder import HEADER  # noqa: E402
from network.relay import (  # noqa: E402
    GAME_PORT,
    RELAY_ALLOW,
    RELAY_VALUES,
    is_block,
    is_relay_traffic,
    normalize,
)
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
    dropped_lock: Counter[str] = field(default_factory=Counter)
    dropped_offender: Counter[str] = field(default_factory=Counter)
    dropped_panic: Counter[str] = field(default_factory=Counter)
    offender_alerts: list[str] = field(default_factory=list)
    events: list[str] = field(default_factory=list)


def replay(
    rows: Iterator[Row] | Sequence[Row],
    relay_mode: str = RELAY_ALLOW,
    auto_block: bool = False,
    journal: PlayerJournal | None = None,
    emit: Callable[[str], Any] = print,
    lock_after: float | None = None,
    offenders: Sequence[str] = (),
    offender_drop: bool = True,
    friends: dict[str, str] | None = None,
    panic_after: float | None = None,
) -> ReplayResult:
    """Rejoue ``rows`` ; ``emit`` reçoit chaque ligne de décision.

    ``lock_after`` : le verrou de session s'active ``lock_after`` secondes après le
    premier paquet (None = jamais). ``offenders`` : IP récidivistes connues au départ
    (mémoire seule, aucun fichier lu ni écrit) ; les IP bloquées pendant le rejeu le
    deviennent aussi. ``offender_drop`` : coupure immédiate. ``friends`` : ip -> pseudo
    (toujours autorisés). ``panic_after`` : bouton panique activé après N secondes."""
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
        offenders=OffenderStore(persist=False, guard=ls.is_rockstar_server),
        offender_drop=offender_drop,
        sound=lambda: None,  # aucun son en rejeu
        friends=dict(friends or {}),
    )
    assert ctrl.offenders is not None
    for ip in offenders:
        if ctrl.offenders.record(ip, "replay", 0.0):
            ctrl.offender_ips[ip] = 1.0
    ctrl._offender_alerted.clear()
    policy = ls.LivePolicy(
        offenders=ctrl.offender_ips, offender_drop=offender_drop, friends=ctrl.friends
    )
    start: float | None = None
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
        if start is None:
            start = ts
        if lock_after is not None and not policy.lock_on and ts - start >= lock_after:
            policy.lock_on = ctrl.session_lock = True
            emit(f"[{ts:.3f}] " + t("replay.lock_on", n=len(policy.seen)))
        if panic_after is not None and not policy.panic and ts - start >= panic_after:
            policy.panic = ctrl.panic = True
            emit(f"[{ts:.3f}] " + t("replay.panic_on"))
        offender_line = ctrl.offender_check(ip, inbound)
        if offender_line:
            res.offender_alerts.append(ip)
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
            # Le CSV ne contient que du trafic UDP capturé sur le port de jeu (filtre de
            # la vue en direct) mais pas le port : on suppose 6672 (le pire cas).
            is_relay_traffic(True, GAME_PORT, size),
        )
        if not drop:
            policy.offender_drop = ctrl.offender_drop
            if policy.drop(inbound, ip):
                drop = True
                if policy.panic:
                    bucket, key = res.dropped_panic, "replay.drop_panic"
                elif ctrl.offender_drop and ip in ctrl.offender_ips:
                    bucket, key = res.dropped_offender, "replay.drop_offender"
                else:
                    bucket, key = res.dropped_lock, "replay.drop_lock"
                if bucket[ip] == 0:
                    emit(f"[{ts:.3f}] " + t(key, ip=ip))
                bucket[ip] += 1
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
    parser.add_argument(
        "--verrou",
        type=float,
        metavar="SECONDES",
        help="active le verrou de session SECONDES après le premier paquet",
    )
    parser.add_argument(
        "--recidiviste",
        action="append",
        default=[],
        metavar="IP",
        help="IP récidiviste connue au départ (répétable, mémoire seule)",
    )
    parser.add_argument(
        "--sans-coupure",
        action="store_true",
        help="récidivistes : alerte seulement, pas de coupure immédiate",
    )
    parser.add_argument(
        "--ami",
        action="append",
        default=[],
        metavar="IP[=PSEUDO]",
        help="ami toujours autorisé (répétable, mémoire seule)",
    )
    parser.add_argument(
        "--panique",
        type=float,
        metavar="SECONDES",
        help="active le bouton panique SECONDES après le premier paquet",
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
            replay(
                read_rows(f),
                normalize(args.relais),
                args.bouclier,
                journal,
                lock_after=args.verrou,
                offenders=args.recidiviste,
                offender_drop=not args.sans_coupure,
                friends=ls.load_friends(
                    dict(
                        (a.split("=", 1) + [""])[:2] if "=" in a else (a, a)
                        for a in args.ami
                    )
                ),
                panic_after=args.panique,
            )
    except (OSError, ValueError) as e:
        print(f"erreur : {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
