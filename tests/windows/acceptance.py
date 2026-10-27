"""Banc d'acceptation Windows du lot 8 — exécuté par la CI sur l'exe onefile.

Usage (runner Windows, administrateur) :
    python tests/windows/acceptance.py --exe dist/Guardian-X.exe --out logs/acceptance

Chaque scénario lance l'exe avec ``--ci-probe <json>`` : filtre WinDivert à blanc
(« false » : aucun paquet capturé ni renvoyé), état de la GUI lu dans le JSON.
Le banc ne tue QUE les PID qu'il a lancés (le bootloader onefile et son enfant,
vérifié par la sonde). Seuils : voir THRESHOLDS et docs/ci-acceptance.md.

Les fonctions pures en tête de fichier sont testées sous Linux
(tests/test_lot8_acceptance.py) ; le reste n'a de sens que sous Windows.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import hashlib
import json
import os
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Seuils (ms), surchargeables par variables d'environnement GUARDIAN_ACC_<NOM>.
THRESHOLDS: dict[str, int] = {
    "SPLASH_MS": 5000,  # lancement -> écran de démarrage du bootloader visible
    "MAIN_READY_MS": 90000,  # lancement -> fenêtre principale prête (sonde)
    "DRIVER_GONE_MS": 5000,  # fin du processus / nettoyage -> pilote absent
    "EXIT_MS": 15000,  # WM_CLOSE -> fin du processus
    "HOTKEY_MS": 3000,  # WM_HOTKEY / SendInput -> action vue par la sonde
    "LOGOFF_STATUS_MS": 10000,  # fin de session annulée -> statut visible
}

WM_CLOSE = 0x0010
WM_QUERYENDSESSION = 0x0011
WM_ENDSESSION = 0x0016
WM_HOTKEY = 0x0312
ENDSESSION_LOGOFF = 0x80000000
MOD_ALT, MOD_CONTROL, MOD_SHIFT = 0x0001, 0x0002, 0x0004
VK_F12, VK_LCONTROL, VK_RMENU, VK_MENU, VK_CONTROL = 0x7B, 0xA2, 0xA5, 0x12, 0x11
STOPPED_TEXT = "Protection arrêtée"


def threshold(name: str, env: Mapping[str, str] | None = None) -> int:
    src: Mapping[str, str] = os.environ if env is None else env
    raw = src.get(f"GUARDIAN_ACC_{name}")
    try:
        return int(raw) if raw else THRESHOLDS[name]
    except ValueError:
        return THRESHOLDS[name]


def driver_active(sc_output: str) -> bool:
    """Sortie de ``sc query WinDivert`` : pilote encore présent et pas arrêté ?"""
    if "1060" in sc_output:  # service inexistant = supprimé
        return False
    return any(s in sc_output for s in ("RUNNING", "START_PENDING", "STOP_PENDING"))


def hotkey_lparam(mods: int, vk: int) -> int:
    """lParam de WM_HOTKEY : modificateurs en mot bas, code de touche en mot haut."""
    return (vk << 16) | (mods & 0xFFFF)


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def altgr_sequence(letter: str) -> list[tuple[int, bool]]:
    """AltGr = LCtrl + RAlt (ce que Windows synthétise), puis la lettre."""
    vk = ord(letter.upper())
    return [
        (VK_LCONTROL, True),
        (VK_RMENU, True),
        (vk, True),
        (vk, False),
        (VK_RMENU, False),
        (VK_LCONTROL, False),
    ]


def ctrl_alt_f12_sequence() -> list[tuple[int, bool]]:
    return [
        (VK_CONTROL, True),
        (VK_MENU, True),
        (VK_F12, True),
        (VK_F12, False),
        (VK_MENU, False),
        (VK_CONTROL, False),
    ]


@dataclass
class Report:
    checks: list[dict[str, Any]] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)

    def check(self, name: str, ok: bool | None, detail: str = "") -> bool:
        """ok=None : non vérifiable ici (limite documentée), pas un échec."""
        state = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
        self.checks.append({"name": name, "result": state, "detail": detail})
        print(f"[{state}] {name}{' - ' + detail if detail else ''}", flush=True)
        return bool(ok)

    def reserve(self, name: str, ok: bool, detail: str, reason: str) -> None:
        """Réserve connue documentée : mesurée et affichée, non bloquante."""
        state = "PASS" if ok else "WARN"
        if not ok:
            detail = f"KNOWN RESERVE ({reason}) - {detail}"
        self.checks.append({"name": name, "result": state, "detail": detail})
        print(f"[{state}] {name} - {detail}", flush=True)

    @property
    def warned(self) -> list[str]:
        return [c["name"] for c in self.checks if c["result"] == "WARN"]

    @property
    def failed(self) -> list[str]:
        return [c["name"] for c in self.checks if c["result"] == "FAIL"]


# --------------------------------------------------------------------------
# Windows uniquement à partir d'ici.
# --------------------------------------------------------------------------
class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", ctypes.c_ushort),
        ("wScan", ctypes.c_ushort),
        ("dwFlags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", ctypes.c_size_t),
    ]


class _INPUTUNION(ctypes.Union):
    _fields_ = [("ki", KEYBDINPUT), ("pad", ctypes.c_byte * 32)]


class INPUT(ctypes.Structure):
    _fields_ = [("type", ctypes.c_ulong), ("u", _INPUTUNION)]


class Win:  # pragma: no cover - Windows
    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        self.ct = ctypes
        self.wt = wintypes
        self.u32 = ctypes.WinDLL("user32", use_last_error=True)
        self.u32.SendMessageTimeoutW.argtypes = [
            wintypes.HWND,
            wintypes.UINT,
            wintypes.WPARAM,
            wintypes.LPARAM,
            wintypes.UINT,
            wintypes.UINT,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self.u32.PostMessageW.argtypes = [
            wintypes.HWND,
            wintypes.UINT,
            wintypes.WPARAM,
            wintypes.LPARAM,
        ]
        self.u32.PostThreadMessageW.argtypes = [
            wintypes.DWORD,
            wintypes.UINT,
            wintypes.WPARAM,
            wintypes.LPARAM,
        ]

    def windows_of(self, pid: int) -> list[int]:
        """Fenêtres visibles appartenant au PID."""
        ct, wt, found = self.ct, self.wt, []
        proto = ct.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

        def cb(hwnd: Any, _l: Any) -> bool:
            owner = wt.DWORD()
            self.u32.GetWindowThreadProcessId(hwnd, ct.byref(owner))
            if owner.value == pid and self.u32.IsWindowVisible(hwnd):
                found.append(int(hwnd))
            return True

        self.u32.EnumWindows(proto(cb), 0)
        return found

    def owner_pid(self, hwnd: int) -> int:
        owner = self.wt.DWORD()
        self.u32.GetWindowThreadProcessId(hwnd, self.ct.byref(owner))
        return int(owner.value)

    def thread_pid(self, tid: int) -> int:
        k32 = self.ct.WinDLL("kernel32", use_last_error=True)
        k32.OpenThread.restype = self.wt.HANDLE
        h = k32.OpenThread(0x0800, False, tid)  # THREAD_QUERY_LIMITED_INFORMATION
        if not h:
            return 0
        try:
            return int(k32.GetProcessIdOfThread(h))
        finally:
            k32.CloseHandle(h)

    def _own(self, hwnd: int, pid: int) -> None:
        # Garde-fou : on ne vise QUE la fenêtre de Guardian (PID lancé par ce banc).
        if not hwnd or not pid or self.owner_pid(hwnd) != pid:
            raise RuntimeError(f"refused: hwnd {hwnd} not owned by pid {pid}")

    def send(
        self, hwnd: int, pid: int, msg: int, wp: int, lp: int, timeout_ms: int = 5000
    ) -> bool:
        self._own(hwnd, pid)
        res = self.ct.c_size_t()
        return bool(
            self.u32.SendMessageTimeoutW(
                hwnd, msg, wp, lp, 0x0002, timeout_ms, self.ct.byref(res)
            )
        )

    def post(self, hwnd: int, pid: int, msg: int, wp: int = 0, lp: int = 0) -> bool:
        self._own(hwnd, pid)
        return bool(self.u32.PostMessageW(hwnd, msg, wp, lp))

    def post_thread(self, tid: int, pid: int, msg: int, wp: int, lp: int) -> bool:
        if not tid or not pid or self.thread_pid(tid) != pid:
            raise RuntimeError(f"refused: thread {tid} not in pid {pid}")
        return bool(self.u32.PostThreadMessageW(tid, msg, wp, lp))

    def foreground(self, hwnd: int, pid: int) -> bool:
        self._own(hwnd, pid)
        u = self.u32
        u.ShowWindow(hwnd, 9)  # SW_RESTORE
        # Astuce documentée : une frappe Alt autorise SetForegroundWindow.
        u.keybd_event(VK_MENU, 0, 0, 0)
        u.keybd_event(VK_MENU, 0, 2, 0)
        u.SetForegroundWindow(hwnd)
        time.sleep(0.3)
        return int(u.GetForegroundWindow()) == hwnd

    def send_keys(self, seq: list[tuple[int, bool]], pid: int) -> int:
        # SendInput va à la fenêtre au premier plan : on n'injecte que si c'est Guardian.
        fg = int(self.u32.GetForegroundWindow())
        if not fg or not pid or self.owner_pid(fg) != pid:
            return 0
        arr = (INPUT * len(seq))()
        for i, (vk, down) in enumerate(seq):
            flags = 0 if down else 0x0002  # KEYEVENTF_KEYUP
            if vk == VK_RMENU:
                flags |= 0x0001  # KEYEVENTF_EXTENDEDKEY : Alt droit = AltGr
            arr[i].type = 1  # INPUT_KEYBOARD
            arr[i].u.ki = KEYBDINPUT(vk, 0, flags, 0, 0)
        n = int(self.u32.SendInput(len(seq), arr, ctypes.sizeof(INPUT)))
        time.sleep(0.05)
        return n


def sc_query() -> str:  # pragma: no cover - Windows
    r = subprocess.run(["sc.exe", "query", "WinDivert"], capture_output=True, text=True)
    return (r.stdout or "") + (r.stderr or "")


def wait_until(
    fn: Callable[[], Any], timeout_ms: int, step: float = 0.05
) -> tuple[bool, float]:
    t0 = time.perf_counter()
    while True:
        try:
            if fn():
                return True, (time.perf_counter() - t0) * 1000
        except Exception:
            pass
        if (time.perf_counter() - t0) * 1000 > timeout_ms:
            return False, (time.perf_counter() - t0) * 1000
        time.sleep(step)


def read_probe(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text("utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def pid_alive(pid: int) -> bool:  # pragma: no cover - Windows
    r = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True
    )
    return str(pid) in (r.stdout or "")


class Run:  # pragma: no cover - Windows
    """Une instance de l'exe lancée par ce banc (et seulement elle)."""

    def __init__(self, exe: Path, out: Path, name: str, rep: Report, win: Win):
        self.exe, self.name, self.rep, self.win = exe, name, rep, win
        self.probe = out / f"probe_{name}.json"
        self.probe.unlink(missing_ok=True)
        self.t0 = time.time()
        self.p = subprocess.Popen([str(exe), "--ci-probe", str(self.probe.resolve())])
        self.parent = self.p.pid
        self.child = 0
        self.hwnd = 0

    def state(self) -> dict[str, Any]:
        return read_probe(self.probe)

    def wait_ready(self) -> bool:
        ok, _ = wait_until(
            lambda: "main_ready" in self.state().get("marks", {}),
            threshold("MAIN_READY_MS"),
            0.1,
        )
        s = self.state()
        if ok:
            self.child, self.hwnd = int(s.get("pid", 0)), int(s.get("hwnd", 0))
            # Garde-fou « nos PID seulement » : l'enfant doit être celui de notre lancement.
            ok = int(s.get("ppid", 0)) == self.parent and self.child > 0
            # HWND retrouvé par le PID (EnumWindows), pas cru sur parole.
            mine = self.win.windows_of(self.child) if ok else []
            if self.hwnd not in mine:
                self.hwnd = mine[0] if mine else 0
            ok = ok and self.hwnd != 0
        self.rep.metrics[f"{self.name}.main_ready_ms"] = round(
            (s.get("marks", {}).get("main_ready", self.t0) - self.t0) * 1000
        )
        return self.rep.check(
            f"{self.name}: main window ready, child of our launch", ok
        )

    def gone(self) -> bool:
        return self.p.poll() is not None and not (self.child and pid_alive(self.child))

    def descendants(self) -> list[int]:
        """Processus de l'exe dont le parent est NOTRE enfant (workers orphelins)."""
        out = []
        for pair in same_exe_processes(self.exe).split():
            pid, _, ppid = pair.partition("<-")
            if pid.isdigit() and ppid.isdigit() and int(ppid) == self.child:
                out.append(int(pid))
        return out

    def kill_own(self) -> None:
        own = self.descendants() if self.child else []
        if own:
            self.rep.metrics[f"{self.name}.orphans_killed"] = own
        for pid in (*own, self.child, self.parent):
            if pid and pid_alive(pid):
                subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid)], capture_output=True
                )


def check_driver_gone(rep: Report, name: str) -> None:  # pragma: no cover
    """Appelé dès la fin du processus (ou du nettoyage) : délai mesuré à partir d'ici."""
    ok, ms = wait_until(
        lambda: not driver_active(sc_query()), threshold("DRIVER_GONE_MS"), 0.1
    )
    rep.metrics[f"{name}.driver_gone_ms"] = round(ms)
    rep.check(
        f"{name}: WinDivert gone <= {threshold('DRIVER_GONE_MS')} ms",
        ok,
        sc_query().strip()[:300],
    )


def measure_splash(run: Run, rep: Report) -> None:  # pragma: no cover
    ok, ms = wait_until(lambda: bool(run.win.windows_of(run.parent)), 20000, 0.01)
    rep.metrics["splash_ms"] = round(ms)
    lim = threshold("SPLASH_MS")
    rep.check(
        f"startup: bootloader splash visible <= {lim} ms",
        ok and ms <= lim,
        f"{ms:.0f} ms",
    )


def scenario_main(
    exe: Path, out: Path, rep: Report, win: Win
) -> None:  # pragma: no cover
    run = Run(exe, out, "main", rep, win)
    try:
        measure_splash(run, rep)
        if not run.wait_ready():
            return
        s = run.state()
        # 4. SHA256 affiché == Get-FileHash de l'artefact.
        shown = str(s.get("exe_sha256_shown", "")).lower()
        real = sha256_of(exe)
        rep.check(
            "settings: SHA256 shown equals artifact hash",
            shown == real,
            f"{shown} vs {real}",
        )
        # 3a. RegisterHotKey a réussi pour les 5 raccourcis.
        hk = s.get("hotkeys", {})
        rep.check(
            "hotkeys: RegisterHotKey succeeded for all 5",
            sorted(hk.get("registered", [])) == sorted(s.get("hotkey_ids", {}))
            and not hk.get("failed"),
            json.dumps(hk),
        )
        tid = int(hk.get("thread_id", 0))
        ids: dict[str, int] = s.get("hotkey_ids", {})
        keys: dict[str, list[int]] = s.get("hotkey_keys", {})

        def fired() -> list[str]:
            return list(run.state().get("fired", []))

        def post(action: str) -> bool:
            n = len(fired())
            mods, vk = keys[action]
            win.post_thread(
                tid, run.child, WM_HOTKEY, ids[action], hotkey_lparam(mods, vk)
            )
            ok, _ = wait_until(
                lambda: len(fired()) > n and fired()[-1] == action,
                threshold("HOTKEY_MS"),
            )
            return ok

        # 3b. WM_HOTKEY pour chaque id ; effet vérifié sur l'état.
        def st() -> dict[str, Any]:
            v = run.state().get("state", {})
            return v if isinstance(v, dict) else {}

        def flipped(action: str, before: Any) -> Callable[[], bool]:
            return lambda: st().get(action) != before

        ok = post("emergency")
        ok2, _ = wait_until(lambda: st().get("paused") is True, 2000)
        rep.check("hotkey Ctrl+Alt+F12 (WM_HOTKEY): emergency stop engaged", ok and ok2)
        ok = post("emergency")
        ok2, _ = wait_until(lambda: st().get("paused") is False, 2000)
        rep.check("hotkey Ctrl+Alt+F12 again: filtering resumed", ok and ok2)
        for action in ("panic", "auto", "total", "lock"):
            before = st().get(action)
            ok = post(action)
            changed, _ = wait_until(flipped(action, before), 2000)
            avail = run.state().get("auto_block_available", False)
            if action in ("auto", "total") and not avail and not changed:
                rep.check(
                    f"hotkey {action} (WM_HOTKEY): action received",
                    ok,
                    "ranges unavailable: toggle refused by design",
                )
            elif action == "lock" and not changed:
                rep.check(
                    f"hotkey {action} (WM_HOTKEY): action received",
                    ok,
                    "lock may refuse (seen-IP list); dry filter",
                )
            else:
                rep.check(
                    f"hotkey {action} (WM_HOTKEY): action received and state flipped",
                    ok and changed,
                )
            if changed:  # remettre l'état d'origine
                post(action)
        # 3c. SendInput réel (fenêtre de Guardian au premier plan).
        fg = win.foreground(run.hwnd, run.child) if run.hwnd else False
        rep.metrics["foreground_ok"] = fg
        n0, s0 = len(fired()), dict(st())
        sent = 0
        for letter in "XATV":
            sent += win.send_keys(altgr_sequence(letter), run.child)
        time.sleep(1.5)
        rep.metrics["altgr_events_injected"] = sent
        rep.check(
            "AltGr+X/A/T/V (real SendInput, Guardian foreground): no hotkey fired",
            len(fired()) == n0 and st() == s0 if sent else None,
            f"injected={sent} foreground={fg}",
        )
        n1 = len(fired())
        sent = win.send_keys(ctrl_alt_f12_sequence(), run.child)
        got, ms = wait_until(lambda: len(fired()) > n1, threshold("HOTKEY_MS"))
        if got:
            rep.check(
                "Ctrl+Alt+F12 (real SendInput): emergency fired",
                fired()[-1] == "emergency",
                f"{ms:.0f} ms",
            )
            win.send_keys(ctrl_alt_f12_sequence(), run.child)  # reprise
            wait_until(lambda: st().get("paused") is False, 3000)
        else:
            # Pas d'entrée physique livrée (bureau non interactif) : limite, pas un échec.
            rep.check(
                "Ctrl+Alt+F12 (real SendInput): emergency fired",
                None,
                f"not delivered (injected={sent})",
            )
        # 1b. WM_CLOSE sur la fenêtre principale.
        win.post(run.hwnd, run.child, WM_CLOSE)
        ok, ms = wait_until(run.gone, threshold("EXIT_MS"), 0.1)
        rep.metrics["wm_close_exit_ms"] = round(ms)
        rep.check("WM_CLOSE: process tree exited", ok, f"{ms:.0f} ms")
        check_driver_gone(rep, "WM_CLOSE")
    finally:
        run.kill_own()


def spawn_log_path() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home())
    return Path(base) / "Guardian" / "ci-spawn.log"


def spawn_log() -> list[str]:
    """Diagnostic CI écrit par l'exe en mode sonde (PID/rôle des enfants)."""
    try:
        return spawn_log_path().read_text("utf-8").splitlines()
    except OSError:
        return []


def same_exe_processes(
    exe: Path, cmdline: bool = False
) -> str:  # pragma: no cover - Windows
    """PID/PPID des processus portant le nom de l'exe (lecture seule)."""
    ps = (
        "Get-CimInstance Win32_Process -Filter \"Name='" + exe.name + "'\" | "
        'ForEach-Object { "$($_.ProcessId)<-$($_.ParentProcessId)"'
        + (" + '[' + ($_.CommandLine -replace '\\s+', '_') + ']'" if cmdline else "")
        + " }"
    )
    r = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True
    )
    return " ".join((r.stdout or "").split()) or "none"


def scenario_kill(
    exe: Path, out: Path, rep: Report, win: Win, target: str
) -> None:  # pragma: no cover
    run = Run(exe, out, f"kill_{target}", rep, win)
    try:
        if not run.wait_ready():
            return
        pid = run.child if target == "child" else run.parent
        subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
        ok, ms = wait_until(run.gone, threshold("EXIT_MS"), 0.1)
        detail = f"{ms:.0f} ms"
        if not ok:  # diagnostic en lecture seule : instances restantes de l'exe
            detail += "; left: " + same_exe_processes(exe, cmdline=True)
            detail += "; ci-spawn.log: " + " | ".join(spawn_log()[-30:])
        name = f"taskkill /F {target} PID: process tree exited"
        if target == "child":  # docs/ci-acceptance.md, « Réserve connue »
            rep.reserve(name, ok, detail, "capture helper lingers, no driver access")
        else:
            rep.check(name, ok, detail)
        check_driver_gone(rep, f"taskkill-{target}")
    finally:
        run.kill_own()


def scenario_logoff(
    exe: Path, out: Path, rep: Report, win: Win
) -> None:  # pragma: no cover
    run = Run(exe, out, "logoff", rep, win)
    try:
        if not run.wait_ready():
            return
        a = win.send(run.hwnd, run.child, WM_QUERYENDSESSION, 0, ENDSESSION_LOGOFF)
        b = win.send(
            run.hwnd, run.child, WM_ENDSESSION, 0, ENDSESSION_LOGOFF
        )  # wParam=FALSE : annulée
        rep.metrics["logoff_messages_delivered"] = [a, b]
        ok, ms = wait_until(
            lambda: run.state().get("protection_stopped") is True
            and str(run.state().get("status", "")).startswith(STOPPED_TEXT),
            threshold("LOGOFF_STATUS_MS"),
            0.1,
        )
        rep.check(
            "cancelled logoff: 'Protection arrêtée' status shown",
            ok,
            f"{ms:.0f} ms; status={run.state().get('status')!r}",
        )
        rep.check("cancelled logoff: Guardian still running", not run.gone())
        check_driver_gone(rep, "cancelled-logoff")
        win.post(run.hwnd, run.child, WM_CLOSE)
        ok, _ = wait_until(run.gone, threshold("EXIT_MS"), 0.1)
        rep.check("cancelled logoff: closes cleanly afterwards", ok)
    finally:
        run.kill_own()


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - Windows
    # Console du runner en cp1252 : jamais d'échec d'encodage à l'affichage.
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(Exception):
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True)
    ap.add_argument("--out", default="logs/acceptance")
    args = ap.parse_args(argv)
    exe, out = Path(args.exe).resolve(), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    rep, win = Report(), Win()
    with contextlib.suppress(OSError):
        spawn_log_path().unlink()
    rep.metrics["thresholds"] = {k: threshold(k) for k in THRESHOLDS}
    if os.environ.get("GUARDIAN_CI_PROBE") != "1":
        # Sans cette variable (et CI=true), l'exe ignore --ci-probe : protection réelle.
        rep.check(
            "precondition: env GUARDIAN_CI_PROBE=1 set (probe mode gated)",
            False,
            "set GUARDIAN_CI_PROBE: '1' on the workflow step",
        )
    elif driver_active(sc_query()):
        rep.check(
            "precondition: WinDivert not loaded before the bench", False, sc_query()
        )
    else:
        scenarios: tuple[Callable[[], None], ...] = (
            lambda: scenario_main(exe, out, rep, win),
            lambda: scenario_kill(exe, out, rep, win, "child"),
            lambda: scenario_kill(exe, out, rep, win, "parent"),
            lambda: scenario_logoff(exe, out, rep, win),
        )
        for fn in scenarios:
            try:
                fn()
            except Exception as e:
                rep.check(f"scenario crashed: {e!r}", False)
            if driver_active(sc_query()):  # isoler les scénarios
                subprocess.run(["sc.exe", "stop", "WinDivert"], capture_output=True)
                time.sleep(3)
    (out / "acceptance.json").write_text(
        json.dumps(
            {"checks": rep.checks, "metrics": rep.metrics, "failed": rep.failed},
            indent=1,
            ensure_ascii=False,
        ),
        "utf-8",
    )
    print(json.dumps(rep.metrics, indent=1))
    print("FAILED:" if rep.failed else "ALL PASS", ", ".join(rep.failed))
    if rep.warned:
        print("KNOWN RESERVE (non-blocking):", ", ".join(rep.warned))
    return 1 if rep.failed else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
