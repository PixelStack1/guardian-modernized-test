"""Rapports d'incident écrits automatiquement à chaque blocage (auto ou manuel).

Deux fichiers par blocage dans %LOCALAPPDATA%\\Guardian\\rapports\\ :
  AAAAMMJJ-HHMMSS_<ip>.txt  (lisible, prêt à coller)
  AAAAMMJJ-HHMMSS_<ip>.json (brut)
Uniquement des MÉTADONNÉES (IP, ports, tailles, débits, horodatages), jamais le
contenu des paquets. Aucun appel réseau. Aucune exception ne remonte à l'appelant.
Seuls les MAX_REPORTS derniers rapports sont conservés.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import platform
import queue
import threading
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any

from network.anomaly import LEVEL_KEYS, Level, PeerState
from util.geoip import country_code
from util.i18n import t
from util.paths import data_dir
from util.version import __version__

logger = logging.getLogger(__name__)

# Nombre de rapports conservés (paires .txt + .json) ; les plus anciens sont supprimés.
MAX_REPORTS = 200
# Nombre de paquets de la fenêtre glissante recopiés dans le rapport (extrait).
WINDOW_EXCERPT = 20

KIND_AUTO = "auto"
KIND_MANUAL = "manual"


def reports_dir() -> Path:
    return data_dir() / "rapports"


def _clock(ts: float) -> str:
    """Heure locale lisible (HH:MM:SS.mmm) pour l'extrait de fenêtre."""
    return datetime.fromtimestamp(ts).astimezone().strftime("%H:%M:%S.%f")[:-3]


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")


def build_report(
    peer: PeerState | None,
    ip: str,
    kind: str,
    now: float,
    pseudo: str = "",
) -> dict[str, Any]:
    """Construit le rapport à partir des données déjà calculées par anomaly.py."""
    anomalous = peer is not None and (peer.level > Level.NORMAL or bool(peer.alert))
    start = now
    if peer is not None:
        start = (
            peer.anomaly_since if anomalous and peer.anomaly_since else peer.first_seen
        )
    start = min(start, now)
    stamp = datetime.fromtimestamp(now).strftime("%Y%m%d-%H%M%S")
    digest = hashlib.sha256(f"{ip}|{now!r}|{kind}".encode()).hexdigest()[:8]
    cc = country_code(ip)
    report: dict[str, Any] = {
        "id": f"{stamp}-{digest}",
        "kind": kind,
        "light": not anomalous,
        "start": _iso(start),
        "end": _iso(now),
        "duration_seconds": round(now - start, 3),
        "guardian_version": __version__,
        "platform": platform.system(),
        "source": {
            "ip": ip,
            "ports": sorted(peer.ports) if peer else [],
            "country": cc,
            # Pas de base ASN hors ligne embarquée : opérateur inconnu.
            "asn": None,
            "direction": "inbound",
        },
        "pseudo": clean_pseudo(pseudo),
    }
    if peer is not None:
        presence = max(peer.last_seen - peer.first_seen, 1e-9)
        evidence: dict[str, Any] = {
            "total_packets": peer.total_packets,
            "total_bytes": peer.total_bytes,
            "max_size": peer.max_size_ever,
        }
        if anomalous:
            observed = peer.window.stats(now)
            evidence.update(
                {
                    "anomaly": peer.reason_key.removeprefix("reason.") or None,
                    "alert": peer.alert,
                    "level": Level(peer.level).name.lower(),
                    "avg_pps": round(peer.total_packets / presence, 1),
                    "peak_pps": round(peer.peak_pps, 1),
                    "baseline_pps": peer.baseline_pps,
                    "observed_pps": round(observed.pps, 1),
                    "observed_avg_size": round(observed.avg_size, 1),
                    "window_excerpt": [
                        {"t": round(ts, 3), "size": size}
                        for ts, size in peer.window.snapshot(WINDOW_EXCERPT)
                    ],
                }
            )
        report["evidence"] = evidence
    return report


def format_text(r: dict[str, Any]) -> str:
    src = r["source"]
    cc = src.get("country")
    ev = r.get("evidence", {})
    lines = [
        t("report.header"),
        "=" * 60,
        f"{t('report.id')} : {r['id']}",
        f"{t('report.kind')} : {t('report.kind.' + r['kind'])}"
        + (f" — {t('report.light')}" if r["light"] else ""),
        f"{t('report.start')} : {r['start']}",
        f"{t('report.end')} : {r['end']}",
        f"{t('report.duration')} : {r['duration_seconds']:.1f} s",
        f"Guardian {r['guardian_version']} — {r['platform']}",
        "",
        f"{t('report.ip')} : {src['ip']}",
        f"{t('report.ports')} : {', '.join(map(str, src['ports'])) or '—'}",
        f"{t('report.country')} : {cc or '—'}",
        f"{t('report.direction')} : {t('report.inbound')}",
        f"{t('report.pseudo')} : {r['pseudo']}",
        "",
        t("report.evidence"),
        f"  {t('report.total_packets')} : {ev.get('total_packets', 0)}",
        f"  {t('report.total_bytes')} : {ev.get('total_bytes', 0)}",
        f"  {t('report.max_size')} : {ev.get('max_size', 0)} o",
    ]
    if not r["light"]:
        base = ev.get("baseline_pps")
        lines += [
            f"  {t('report.anomaly')} : {t('reason.' + ev['anomaly']) if ev.get('anomaly') else '—'}"
            f" ({t(LEVEL_KEYS[Level[ev['level'].upper()]])})",
            f"  {t('report.alert')} : {ev.get('alert', '')}",
            f"  {t('report.avg_pps')} : {ev['avg_pps']}   {t('report.peak_pps')} : {ev['peak_pps']}",
            f"  {t('report.baseline')} : {'—' if base is None else f'{base:.0f}'} "
            f"→ {t('report.observed')} : {ev['observed_pps']}",
            f"  {t('report.excerpt')} :",
        ]
        lines += [f"    {_clock(e['t'])}  {e['size']} o" for e in ev["window_excerpt"]]
    else:
        lines.append(f"  {t('report.no_anomaly')}")
    lines += ["", t("report.disclaimer"), ""]
    return "\n".join(lines)


def clean_pseudo(pseudo: str) -> str:
    """Pseudo sur une seule ligne, 64 caractères max (pas d'injection de lignes)."""
    return pseudo.replace("\n", " ").replace("\r", " ")[:64].strip()


def _safe_name(ip: str) -> str:
    return "".join(c if c.isalnum() or c in ".-" else "_" for c in ip)[:64]


def rotate(directory: Path, keep: int = MAX_REPORTS) -> None:
    with contextlib.suppress(OSError):
        reports = sorted(directory.glob("*.json"))
        doomed = [
            p
            for old in reports[: max(0, len(reports) - keep)]
            for p in (old, old.with_suffix(".txt"))
        ]
        # .txt orphelins (sans .json associé, ex. écriture interrompue).
        doomed += [
            p for p in directory.glob("*.txt") if not p.with_suffix(".json").exists()
        ]
        for path in doomed:
            with contextlib.suppress(OSError):
                path.unlink(missing_ok=True)


def write_report(
    report: dict[str, Any], directory: Path | None = None
) -> tuple[Path, Path] | None:
    """Écrit .txt + .json ; renvoie leurs chemins, ou None en cas d'erreur (jamais d'exception)."""
    try:
        directory = directory or reports_dir()
        directory.mkdir(parents=True, exist_ok=True)
        stem = f"{report['id'].rsplit('-', 1)[0]}_{_safe_name(report['source']['ip'])}"
        name, n = stem, 1
        while (directory / f"{name}.json").exists() or (
            directory / f"{name}.txt"
        ).exists():
            n += 1
            name = f"{stem}_{n}"
        txt, js = directory / f"{name}.txt", directory / f"{name}.json"
        for path, content in (
            (txt, format_text(report)),
            (js, json.dumps(report, ensure_ascii=False, indent=2)),
        ):
            tmp = path.with_name(path.name + ".tmp")
            try:
                tmp.write_text(content, encoding="utf-8")
                os.replace(tmp, path)
            except BaseException:
                with contextlib.suppress(OSError):
                    tmp.unlink(missing_ok=True)
                raise
        rotate(directory)
        return txt, js
    except Exception as e:  # disque plein, droits, etc. : ne jamais casser la vue
        logger.warning("Écriture du rapport d'incident impossible : %s", e)
        return None


class ReportWriter:
    """Écrit les rapports dans un thread dédié (hors capture et hors affichage)."""

    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=1000)
        self.written: deque[Path] = deque(maxlen=MAX_REPORTS)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def submit(self, report: dict[str, Any]) -> None:
        with contextlib.suppress(queue.Full):
            self._queue.put_nowait(report)

    def _run(self) -> None:
        while (report := self._queue.get()) is not None:
            paths = write_report(report, self.directory)
            if paths:
                self.written.append(paths[0])
            self._queue.task_done()
        self._queue.task_done()

    def close(self, timeout: float = 5.0) -> None:
        with contextlib.suppress(queue.Full):
            self._queue.put(None, timeout=timeout)
        self._thread.join(timeout)
