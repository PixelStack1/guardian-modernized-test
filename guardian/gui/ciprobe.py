"""Sonde d'état pour le banc d'acceptation Windows (lot 8, ``--ci-probe``).

Écrit atomiquement un JSON lisible par tests/windows/acceptance.py. Uniquement
de l'état d'interface (aucune IP, aucun paquet). Inerte sans ``--ci-probe``.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any

from util.hotkeys import DEFAULT_HOTKEYS

# Liste blanche des clés écrites : rien d'autre ne sort (aucune IP, aucune session).
ALLOWED_KEYS = frozenset(
    {
        "pid",
        "ppid",
        "written",
        "marks",
        "fired",
        "hotkey_ids",
        "hotkey_keys",
        "hwnd",
        "title",
        "status",
        "status_ok",
        "protection_stopped",
        "hotkeys",
        "exe_sha256_shown",
        "state",
        "auto_block_available",
    }
)
HOTKEY_KEYS = frozenset({"registered", "failed", "error", "thread_id"})
STATE_KEYS = frozenset({"paused", "panic", "auto", "total", "lock"})
_IP_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{0,4}:){3,7}[0-9a-fA-F]{0,4}\b"
)


def redact(text: str) -> str:
    """Masque toute adresse IPv4/IPv6 éventuelle dans un texte d'interface."""
    return _IP_RE.sub("<ip>", text)


def sanitize(data: dict[str, Any]) -> dict[str, Any]:
    """Applique la liste blanche et masque les IP dans les textes libres."""
    out = {k: v for k, v in data.items() if k in ALLOWED_KEYS}
    for k in ("title", "status"):
        if k in out:
            out[k] = redact(str(out[k]))
    if isinstance(out.get("hotkeys"), dict):
        hk = {k: v for k, v in out["hotkeys"].items() if k in HOTKEY_KEYS}
        if "error" in hk:
            hk["error"] = redact(str(hk["error"]))
        out["hotkeys"] = hk
    if isinstance(out.get("state"), dict):
        out["state"] = {k: v for k, v in out["state"].items() if k in STATE_KEYS}
    return out


def write_json(path: Path, data: dict[str, Any]) -> None:
    """Écriture atomique (fichier temporaire puis remplacement). Jamais d'exception."""
    with contextlib.suppress(Exception):
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), "utf-8")
        os.replace(tmp, path)


def snapshot(win: Any, fired: list[str], marks: dict[str, float]) -> dict[str, Any]:
    """État observable de la fenêtre principale (tolérant aux erreurs)."""
    data: dict[str, Any] = {
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "written": time.time(),
        "marks": dict(marks),
        "fired": list(fired),
        "hotkey_ids": {h.action: i for i, h in enumerate(DEFAULT_HOTKEYS, 1)},
        "hotkey_keys": {h.action: [h.mods, h.vk] for h in DEFAULT_HOTKEYS},
    }
    with contextlib.suppress(Exception):
        data["hwnd"] = int(win.winId())
    with contextlib.suppress(Exception):
        data["title"] = str(win.windowTitle())
    with contextlib.suppress(Exception):
        data["status"] = str(win.status.text())
        data["status_ok"] = win.status.objectName() == "statusOk"
    data["protection_stopped"] = bool(getattr(win, "protection_stopped", False))
    hk = getattr(win, "hotkeys", None)
    data["hotkeys"] = {
        "registered": list(getattr(hk, "registered", []) or []),
        "failed": list(getattr(hk, "failed", []) or []),
        "error": str(getattr(hk, "error", "") or ""),
        "thread_id": int(getattr(hk, "_thread_id", 0) or 0),
    }
    with contextlib.suppress(Exception):
        data["exe_sha256_shown"] = str(win.settings.exe_hash.text())
    ctrl = getattr(getattr(win, "session", None), "ctrl", None)
    if ctrl is not None:
        state: dict[str, bool] = {}
        for key, attr in (
            ("paused", "filtering_paused"),
            ("panic", "panic"),
            ("auto", "auto_block"),
            ("total", "total_block"),
            ("lock", "session_lock"),
        ):
            with contextlib.suppress(Exception):
                state[key] = bool(getattr(ctrl, attr))
        data["state"] = state
        data["auto_block_available"] = bool(
            getattr(ctrl, "auto_block_available", False)
        )
    return data


class CiProbe:
    """Rattachée à la fenêtre : note les raccourcis reçus et écrit l'état."""

    def __init__(self, path: Path, marks: dict[str, float] | None = None) -> None:
        self.path = path
        self.marks: dict[str, float] = dict(marks or {})
        self.fired: list[str] = []
        self.win: Any = None
        self.timer: Any = None

    def mark(self, name: str) -> None:
        self.marks[name] = time.time()
        self.write()

    def on_fired(self, action: str) -> None:
        self.fired.append(action)

    def attach(self, win: Any, interval_ms: int = 200) -> None:
        self.win = win
        with contextlib.suppress(Exception):
            win.show_ci_banner()
        with contextlib.suppress(Exception):
            win._bridge.fired.connect(self.on_fired)
        from PySide6.QtCore import QTimer

        self.timer = QTimer(win)
        self.timer.setInterval(interval_ms)
        self.timer.timeout.connect(self.write)
        self.timer.start()
        self.mark("main_ready")

    def write(self) -> None:
        if self.win is None:
            data: dict[str, Any] = {
                "pid": os.getpid(),
                "ppid": os.getppid(),
                "written": time.time(),
                "marks": dict(self.marks),
            }
        else:
            data = snapshot(self.win, self.fired, self.marks)
        write_json(self.path, sanitize(data))
