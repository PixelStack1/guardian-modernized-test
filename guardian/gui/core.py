"""Partie sans Qt de la GUI : instantanés de session et actions (= touches console)."""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import re
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from menu import livesession as ls
from network.anomaly import (
    LEVEL_KEYS,
    SHIELD_PPS_KEY,
    SHIELD_SECONDS_KEY,
    Level,
    clamp_shield_pps,
    clamp_shield_seconds,
)
from network.blackbox import CONFIG_KEY as RECORDING_KEY
from network.blackbox import clamp_seconds
from network.filters import (
    PING_KEY,
    RATE_KEY,
    TRUSTED_DEFAULT,
    TRUSTED_KEY,
    VPN_BLOCK_KEY,
    VPN_FLAG_KEY,
    FilterSettings,
)
from util.geoip import country_code
from util.i18n import t

logger = logging.getLogger(__name__)

NEW_PLAYER_SECONDS = 60.0
MAX_EVENTS = 50
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_GREEN = "\x1b[32m"


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


@dataclass(frozen=True)
class Row:
    ip: str
    label: str
    country: str
    ping_ms: float | None
    pps: float
    status: str
    level: int
    badges: tuple[str, ...]
    new: bool
    friend: bool
    recidivist: bool
    server: bool
    blocked: bool
    pseudo: str


@dataclass(frozen=True)
class Snapshot:
    rows: tuple[Row, ...] = ()
    players: int = 0
    blocked: int = 0
    total_pps: float = 0.0
    auto_block: bool = False
    total_block: bool = False
    session_lock: bool = False
    relay_block: bool = False
    panic: bool = False
    offender_sound: bool = False
    offender_drop: bool = False
    recording: bool = False
    recording_path: str = ""
    overflow: bool = False
    ranges_ok: bool = True
    alive: bool = True
    events: tuple[str, ...] = ()
    toggle: tuple[str, bool] | None = None
    blocked_list: tuple[tuple[str, str], ...] = ()
    friends: tuple[tuple[str, str], ...] = ()
    offenders: int = 0
    blackbox_seconds: int = 0


def toggle_message(ctrl: Any) -> tuple[str, bool] | None:
    """Dernier message de bascule (jamais empilé) : (texte, vert ?)."""
    lines = ls.toggle_line(ctrl)
    if not lines:
        return None
    raw = lines[-1]
    return strip_ansi(raw), _GREEN in raw


def take_snapshot(session: Any, now: float | None = None) -> Snapshot:
    """Copie rapide de l'état (sous le verrou de la session, jamais dans la capture)."""
    with session.lock:
        ctrl = session.ctrl
        peers = list(session.peers)
        now = session.now if now is None else now
        filters = ctrl.filters
        tracker = getattr(session, "new_players", None)
        seen_new = getattr(tracker, "seen", {}) if tracker is not None else {}
        rows: list[Row] = []
        total = 0.0
        for p in peers:
            try:
                pps = float(p.window.stats(now).pps)
            except Exception:
                pps = 0.0
            server = ls.is_rockstar_server(p.ip)
            total += pps
            status = ctrl.block_status(p.ip)
            if server:
                status = t("live.rockstar_server")
            elif not status:
                status = (
                    t("level.learning")
                    if p.learning(now)
                    else t(LEVEL_KEYS[Level(p.level)])
                )
            ping: float | None = None
            badges: tuple[str, ...] = ()
            if filters is not None:
                with contextlib.suppress(Exception):
                    ping = filters.ping.estimate(p.ip)
                with contextlib.suppress(Exception):
                    b = filters.badges(p.ip)
                    badges = tuple(x for x in b.split(",") if x)
            rows.append(
                Row(
                    ip=p.ip,
                    label=ctrl.label(p.ip),
                    country=country_code(p.ip) or "—",
                    ping_ms=ping,
                    pps=pps,
                    status=status,
                    level=int(p.level),
                    badges=badges,
                    new=p.ip in seen_new
                    and now - float(p.first_seen) <= NEW_PLAYER_SECONDS,
                    friend=ctrl.is_friend(p.ip),
                    recidivist=p.ip in ctrl.offender_ips,
                    server=server,
                    blocked=p.ip in ctrl.blocked,
                    pseudo=ctrl.pseudos.get(p.ip, ""),
                )
            )
        blocked_list = tuple(
            (ip, ctrl.block_status(ip)) for ip in list(ctrl.blocked.keys())
        )
        players = sum(1 for r in rows if not r.server)
        rec = session.recorder
        bb = getattr(session, "blackbox", None)
        return Snapshot(
            rows=tuple(rows),
            players=players,
            blocked=len(blocked_list),
            total_pps=total,
            auto_block=bool(ctrl.auto_block),
            total_block=bool(ctrl.total_block),
            session_lock=bool(ctrl.session_lock),
            relay_block=bool(ctrl.relay_block),
            panic=bool(ctrl.panic),
            offender_sound=bool(ctrl.offender_sound),
            offender_drop=bool(ctrl.offender_drop),
            recording=bool(getattr(rec, "active", False)),
            recording_path=str(getattr(rec, "path", "") or ""),
            overflow=bool(ctrl.seen_overflow),
            ranges_ok=bool(ctrl.auto_block_available),
            alive=session.alive() or not session.started,
            events=tuple(strip_ansi(e) for e in ctrl.events[-MAX_EVENTS:]),
            toggle=toggle_message(ctrl),
            blocked_list=blocked_list,
            friends=tuple(dict(ctrl.friends).items()),
            offenders=len(ctrl.offenders) if ctrl.offenders is not None else 0,
            blackbox_seconds=int(getattr(bb, "seconds", 0) or 0),
        )


@dataclass
class Settings:
    """Toutes les valeurs de data.json réglables depuis la GUI."""

    trusted_countries: list[str] = field(default_factory=list)
    ping_max_ms: float = 0.0
    rate_limit_pps: int = 0
    shield_pps: int = 0
    shield_seconds: float = 0.0
    recording_seconds: int = 0
    vpn_flag: bool = False
    vpn_auto_block: bool = False


def clean_countries(codes: Iterable[object]) -> list[str]:
    out: list[str] = []
    for c in codes:
        if isinstance(c, str):
            c = c.strip().upper()
            if len(c) == 2 and c.isascii() and c.isalpha() and c not in out:
                out.append(c)
    return out


def read_settings(data: Mapping[str, Any] | None) -> Settings:
    data = data if isinstance(data, Mapping) else {}
    f = FilterSettings.from_config(data)
    raw = data.get(TRUSTED_KEY)
    extra = clean_countries(raw if isinstance(raw, list) else [])
    return Settings(
        trusted_countries=sorted(set(TRUSTED_DEFAULT) | set(extra)),
        ping_max_ms=f.ping_max_ms,
        rate_limit_pps=f.rate_pps,
        shield_pps=clamp_shield_pps(data.get(SHIELD_PPS_KEY)),
        shield_seconds=clamp_shield_seconds(data.get(SHIELD_SECONDS_KEY)),
        recording_seconds=clamp_seconds(data.get(RECORDING_KEY)),
        vpn_flag=f.vpn_flag,
        vpn_auto_block=f.vpn_auto_block,
    )


class GuiActions:
    """Chaque bouton = la touche console correspondante, via ``handle_key``.

    Les réponses aux invites (n° de ligne, pseudo) sont fournies d'avance au lieu
    d'être tapées : même code, mêmes garde-fous, mêmes sauvegardes."""

    def __init__(self, session: Any) -> None:
        self.session = session

    @property
    def ctrl(self) -> Any:
        return self.session.ctrl

    def key(self, key: str, answers: Iterable[str] = ()) -> None:
        it = iter(list(answers))

        def prompt(_text: str) -> str:
            return next(it, "")

        s = self.session
        with s.lock:
            peers = list(s.peers)
            try:
                ls.handle_key(
                    key,
                    s.ctrl,
                    peers,
                    s.blocked,
                    s.recorder,
                    prompt,
                    s.config,
                    blackbox=getattr(s, "blackbox", None),
                )
            except Exception:
                logger.exception("gui : action %r impossible", key)
                s.ctrl.events.append(t("live.action_error", action=key.upper()))

    def _row(self, ip: str) -> str | None:
        with self.session.lock:
            for i, p in enumerate(self.session.peers, 1):
                if p.ip == ip:
                    return str(i)
        return None

    # Bascules (touches A T V L X S C E K).
    def toggle_auto(self) -> None:
        self.key("a")

    def toggle_total(self) -> None:
        self.key("t")

    def toggle_lock(self) -> None:
        self.key("v")

    def toggle_relay(self) -> None:
        self.key("l")

    def set_relay_block(self, block: bool) -> None:
        if bool(self.ctrl.relay_block) != block:
            self.key("l")

    def toggle_panic(self) -> None:
        self.key("x")

    def toggle_sound(self) -> None:
        self.key("s")

    def toggle_cut(self) -> None:
        self.key("c")

    def toggle_recording(self) -> None:
        self.key("e")

    def kick_capture(self) -> None:
        self.key("k")

    # Actions sur une IP (touches B D F P).
    def block(self, ip: str, pseudo: str = "") -> bool:
        row = self._row(ip)
        if row is None:
            return False
        self.key("b", [row, pseudo])
        return True

    def unblock(self, ip: str) -> bool:
        with self.session.lock:
            ips = list(self.session.blocked.keys())
        if ip not in ips:
            return False
        self.key("d", [str(ips.index(ip) + 1)])
        return True

    def toggle_friend(self, ip: str, nick: str = "") -> bool:
        row = self._row(ip)
        if row is None:
            return False
        self.key("f", [row, nick])
        return True

    def add_friend_ip(self, ip: str, nick: str) -> bool:
        """Ami hors session (IP saisie) : mêmes fonctions que F (add_friend + sauvegarde)."""
        ip = ip.strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return False
        if ls.is_rockstar_server(ip):
            return False
        with self.session.lock:
            ok = bool(self.ctrl.add_friend(ip, nick))
            if ok:
                ls._save_friends(self.session.config, self.ctrl)
        return ok

    def remove_friend_ip(self, ip: str) -> bool:
        with self.session.lock:
            ok = bool(self.ctrl.remove_friend(ip))
            if ok:
                ls._save_friends(self.session.config, self.ctrl)
        return ok

    def set_pseudo(self, ip: str, pseudo: str) -> bool:
        row = self._row(ip)
        if row is None:
            return False
        self.key("p", [row, pseudo])
        return True

    # Réglages (data.json), appliqués immédiatement à la session.
    def settings(self) -> Settings:
        config = self.session.config
        return read_settings(getattr(config, "data", None))

    def apply_settings(self, new: Settings) -> Settings:
        s = self.session
        values: dict[str, Any] = {
            TRUSTED_KEY: clean_countries(new.trusted_countries),
            PING_KEY: float(new.ping_max_ms),
            RATE_KEY: int(new.rate_limit_pps),
            SHIELD_PPS_KEY: clamp_shield_pps(new.shield_pps),
            SHIELD_SECONDS_KEY: clamp_shield_seconds(new.shield_seconds),
            RECORDING_KEY: clamp_seconds(new.recording_seconds),
            VPN_FLAG_KEY: bool(new.vpn_flag),
            VPN_BLOCK_KEY: bool(new.vpn_auto_block),
        }
        with s.lock:
            config = s.config
            data = getattr(config, "data", None)
            if not isinstance(data, dict):
                data = {}
            data.update(values)
            if config is not None:
                try:
                    config.save()
                except Exception:
                    logger.debug("sauvegarde des réglages impossible", exc_info=True)
            if s.ctrl.filters is not None:
                with contextlib.suppress(Exception):
                    s.ctrl.filters.settings = FilterSettings.from_config(data)
            with contextlib.suppress(Exception):
                s.monitor.set_shield(values[SHIELD_PPS_KEY], values[SHIELD_SECONDS_KEY])
            bb = getattr(s, "blackbox", None)
            if bb is not None:
                with contextlib.suppress(Exception):
                    bb.seconds = values[RECORDING_KEY]
            return read_settings(data)


# -- Rapports et enregistrements (lecture seule) ------------------------------
@dataclass(frozen=True)
class DataFile:
    """Fichier du dossier de données : nom, taille (octets), date de modification."""

    name: str
    size: int
    mtime: float

    def when(self) -> str:
        return time.strftime("%d/%m/%Y %H:%M:%S", time.localtime(self.mtime))


def list_files(directory: Path | None, pattern: str) -> list[DataFile]:
    """Liste ``pattern`` dans ``directory``, du plus récent au plus ancien.

    Lecture seule : ne crée pas le dossier, ne lit pas le contenu des fichiers ;
    toute erreur donne une liste vide (ou partielle)."""
    out: list[DataFile] = []
    if directory is None:
        return out
    try:
        paths = list(directory.glob(pattern)) if directory.is_dir() else []
    except OSError:
        return out
    for path in paths:
        try:
            st = path.stat()
        except OSError:
            continue
        if path.is_file() and not path.name.startswith("."):
            out.append(DataFile(path.name, int(st.st_size), float(st.st_mtime)))
    out.sort(key=lambda f: (f.mtime, f.name), reverse=True)
    return out


def reports_directory() -> Path | None:
    try:
        from network.incident import reports_dir

        return reports_dir()
    except Exception:
        return None


def recordings_directory(session: Any) -> Path | None:
    """Dossier des enregistrements de la boîte noire, sans le créer."""
    bb = getattr(session, "blackbox", None)
    d = getattr(bb, "_directory", None)
    try:
        if d is not None:
            return Path(d() if callable(d) else d)
        from network.recorder import recordings_dir

        return recordings_dir()
    except Exception:
        return None
