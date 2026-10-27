"""Onefile parent watchdog.

A PyInstaller *onefile* exe is two processes: the bootloader (parent) unpacks
the bundle and waits while the real Python program runs in a child.  Killing
only the parent PID (Task Manager "end task" on the visible PID, CI's
``Stop-Process -Id``) used to leave the child alive, still holding its WinDivert
handle: the driver then sits in STOP_PENDING and the next Guardian start blocks
in WinDivertOpen.  When the parent disappears, the child now runs the normal
cleanup (pre-cleanup, children, driver unregister) and exits.
"""

from __future__ import annotations

import contextlib
import logging
import os
import sys
import threading
import time
from collections.abc import Callable
from typing import Any

SYNCHRONIZE = 0x00100000
WAIT_TIMEOUT = 0x00000102


def is_onefile_child() -> bool:
    """True when running as the child of a PyInstaller onefile bootloader."""
    meipass = getattr(sys, "_MEIPASS", None)
    if not getattr(sys, "frozen", False) or not meipass:
        return False
    if not os.path.basename(os.path.normpath(meipass)).startswith("_MEI"):
        return False  # onedir (_internal) : pas de bootloader parent
    exe_dir = os.path.normcase(os.path.abspath(os.path.dirname(sys.executable)))
    return bool(exe_dir != os.path.normcase(os.path.abspath(meipass)))


def windows_parent_probe(
    kernel32: Any = None, pid: int | None = None
) -> Callable[[], bool] | None:
    """Return a callable "is the parent still alive?" bound to a handle opened now
    (immune to PID reuse), or None if unavailable."""
    try:
        if kernel32 is None:
            if sys.platform != "win32":
                return None
            import ctypes

            kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(
            SYNCHRONIZE, False, os.getppid() if pid is None else pid
        )
        if not handle:
            return None
    except Exception:
        return None

    def alive() -> bool:
        try:
            return bool(kernel32.WaitForSingleObject(handle, 0) == WAIT_TIMEOUT)
        except Exception:
            return True  # fail-open: never tear down on a probe error

    return alive


def start_parent_watchdog(
    alive: Callable[[], bool],
    on_parent_exit: Callable[[], Any],
    exit_fn: Callable[[int], Any] = os._exit,
    interval: float = 1.0,
    cleanup_timeout: float = 12.0,
) -> threading.Thread:
    """Daemon thread: when ``alive()`` turns False, run ``on_parent_exit`` then exit."""
    stop = threading.Event()

    def run() -> None:
        while not stop.wait(interval):
            if alive():
                continue

            # Nettoyage borné dans le temps : un appel bloqué (ex. fermeture d'un
            # handle pendant une lecture) ne doit jamais empêcher la sortie, qui
            # ferme de toute façon les handles du processus.
            def guarded() -> None:
                try:
                    on_parent_exit()
                except Exception:
                    logging.getLogger("debugger").exception(
                        "parent watchdog: cleanup after parent exit failed"
                    )

            worker = threading.Thread(target=guarded, name="parent-exit-cleanup")
            worker.daemon = True
            worker.start()
            worker.join(cleanup_timeout)
            exit_fn(0)
            return

    t = threading.Thread(target=run, name="parent-watchdog", daemon=True)
    t.start()
    return t


_worker_watch_started = False
WORKER_CLEANUP_S = 4.0  # worker orphelin : nettoyage borné puis sortie


def _no_cleanup() -> None:
    return None


def watch_worker_parent(
    probe: Callable[[int], Callable[[], bool] | None] | None = None,
    start: Callable[..., Any] = start_parent_watchdog,
    on_parent_exit: Callable[[], Any] | None = None,
) -> bool:
    """Capture workers (multiprocessing children holding a WinDivert handle):
    exit when the GUI process that spawned them disappears (taskkill /F, crash),
    so the handle closes and the driver can unload — fail-open, never an orphan
    diverting traffic. No-op in the main process; idempotent."""
    global _worker_watch_started
    import multiprocessing

    parent = multiprocessing.parent_process()
    ppid = getattr(parent, "pid", None)
    if _worker_watch_started or not ppid:
        return False
    # PID du processus qui a lancé le worker (la GUI), pas os.getppid() : en onefile
    # le worker passe par son propre bootloader, qui serait alors le « parent ».
    alive = windows_parent_probe(pid=ppid) if probe is None else probe(ppid)
    if alive is None:
        return False
    start(alive, on_parent_exit or _no_cleanup, cleanup_timeout=WORKER_CLEANUP_S)
    _worker_watch_started = True
    return True


def spawn_parent_pid(argv: list[str]) -> int | None:
    """PID du lanceur d'un enfant multiprocessing (``--multiprocessing-fork
    parent_pid=N …``), sinon None."""
    if "--multiprocessing-fork" not in argv:
        return None
    for arg in argv:
        if arg.startswith("parent_pid="):
            try:
                pid = int(arg.split("=", 1)[1])
            except ValueError:
                return None
            return pid if pid > 0 else None
    return None


def watch_spawn_parent(
    argv: list[str],
    probe: Callable[[int], Callable[[], bool] | None] | None = None,
    start: Callable[..., Any] = start_parent_watchdog,
    on_parent_exit: Callable[[], Any] | None = None,
) -> bool:
    """Tout enfant multiprocessing (worker de capture, serveur Manager) se termine
    quand son lanceur (la GUI) disparaît — handle WinDivert fermé, aucun orphelin.
    À appeler avant freeze_support(). No-op hors enfant multiprocessing."""
    global _worker_watch_started
    pid = spawn_parent_pid(argv)
    if pid is None or _worker_watch_started:
        return False
    alive = windows_parent_probe(pid=pid) if probe is None else probe(pid)
    if alive is None:
        return False
    start(alive, on_parent_exit or _no_cleanup, cleanup_timeout=WORKER_CLEANUP_S)
    _worker_watch_started = True
    return True


def ci_diag(line: str) -> None:
    """Trace de diagnostic, écrite UNIQUEMENT en mode sonde CI (GUARDIAN_CI_DRY=1,
    hérité des enfants) dans %LOCALAPPDATA%\\Guardian\\ci-spawn.log. Inerte sinon."""
    try:
        from util import cimode

        if not cimode.dry():  # DRY_ENV=1 ET contexte CI autorisé
            return
    except Exception:
        return
    with contextlib.suppress(Exception):
        import time

        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        path = os.path.join(base, "Guardian", "ci-spawn.log")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{time.time():.3f} pid={os.getpid()} {line}\n")


CRASH_LOG = "ci-crash.log"


def ci_crash_path() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "Guardian", CRASH_LOG)


def ci_traceback(where: str, text: str | None = None) -> None:
    """Traceback complet d'une exception non gérée (enfant multiprocessing, fil),
    écrit UNIQUEMENT en mode sonde CI dans %LOCALAPPDATA%\\Guardian\\ci-crash.log.
    En exe fenêtré, sys.stderr vaut None : sans ce journal, le traceback n'existe
    que dans la boîte « Unhandled exception in script » du chargeur. Inerte sinon,
    jamais d'exception."""
    try:
        from util import cimode

        if not cimode.dry():
            return
    except Exception:
        return
    with contextlib.suppress(Exception):
        import traceback

        body = text if text is not None else traceback.format_exc()
        path = ci_crash_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(
                f"=== {time.time():.3f} pid={os.getpid()} where={where} "
                f"argv={sys.argv[1:4]}\n{body}\n"
            )


def install_ci_thread_hook() -> None:
    """Mode sonde CI : les exceptions non gérées des fils sont aussi journalisées
    (puis transmises au crochet précédent). Inerte hors CI."""
    with contextlib.suppress(Exception):
        from util import cimode

        if not cimode.dry():
            return
        previous = threading.excepthook

        def hook(args: Any) -> None:
            import traceback

            text = "".join(
                traceback.format_exception(
                    args.exc_type, args.exc_value, args.exc_traceback
                )
            )
            name = getattr(args.thread, "name", "?")
            ci_traceback(f"thread {name}", text)
            with contextlib.suppress(Exception):
                previous(args)

        threading.excepthook = hook


def log_spawn(purpose: str, pid: Any) -> None:
    """PID + rôle de chaque enfant lancé (journal + diagnostic CI)."""
    logging.getLogger(__name__).info("spawned child pid=%s purpose=%s", pid, purpose)
    ci_diag(f"spawned child pid={pid} purpose={purpose}")


def arm_with_pid(
    gui_pid: int,
    purpose: str = "child",
    on_exit: Callable[[], object] | None = None,
    cleanup_timeout: float = WORKER_CLEANUP_S,
) -> None:
    """Entrée d'un enfant (initialiseur Manager / début de cible Process) : fil
    dédié qui attend la fin du processus ``gui_pid`` (OpenProcess SYNCHRONIZE +
    WaitForSingleObject INFINITE) puis ``os._exit(0)``. Indépendant des autres
    armements ; fail-open (aucun effet si l'ouverture échoue)."""
    ci_diag(f"arm purpose={purpose} gui_pid={gui_pid}")
    if sys.platform != "win32" or not gui_pid:
        return
    try:
        import ctypes
        from ctypes import wintypes as wt

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.restype = wt.HANDLE
        k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        k32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
        k32.WaitForSingleObject.restype = wt.DWORD
        h = k32.OpenProcess(SYNCHRONIZE, False, gui_pid)
        if not h:
            ci_diag(f"arm failed OpenProcess err={ctypes.get_last_error()}")
            return
    except Exception as e:
        ci_diag(f"arm failed {e!r}")
        return

    def wait_then_exit() -> None:
        r = k32.WaitForSingleObject(h, 0xFFFFFFFF)
        ci_diag(f"gui gone (wait={r}) -> exit purpose={purpose}")
        if on_exit is not None:
            # nettoyage borné (fermeture handles + désenregistrement) puis sortie dure
            def _run() -> None:
                with contextlib.suppress(Exception):
                    ci_diag(f"cleanup steps={on_exit()} purpose={purpose}")

            t = threading.Thread(target=_run, daemon=True)
            t.start()
            t.join(cleanup_timeout)
            ci_diag(f"cleanup done={not t.is_alive()} purpose={purpose}")
        os._exit(0)

    threading.Thread(target=wait_then_exit, name="gui-watch", daemon=True).start()
    ci_diag(f"armed purpose={purpose}")


def arm_in_child(gui_pid: int = 0) -> None:
    """Initialiseur des serveurs Manager (point d'entrée réel du serveur)."""
    try:
        from util.driver import orphan_cleanup

        arm_with_pid(gui_pid, "Manager server", on_exit=orphan_cleanup)
        watch_worker_parent()
    except Exception:
        logging.getLogger("debugger").exception("manager parent watchdog failed")


def watched_manager() -> Any:
    """Comme ``multiprocessing.Manager()``, mais le serveur meurt avec la GUI."""
    from multiprocessing.managers import SyncManager

    manager = SyncManager()
    manager.start(initializer=arm_in_child, initargs=(os.getpid(),))
    log_spawn("Manager server", getattr(getattr(manager, "_process", None), "pid", "?"))
    return manager


def _orphan_cleanup_lazy() -> None:
    from util.driver import orphan_cleanup

    orphan_cleanup()


def auto_arm(argv: list[str] | None = None) -> bool:
    """Armement à l'import dans tout enfant multiprocessing qui charge nos modules
    (cible ou initialiseur dépicklé). ``parent_process()`` n'y est pas encore
    défini (spawn le pose après le dépicklage), d'où l'argv ``parent_pid=N``."""
    try:
        return watch_spawn_parent(
            sys.argv if argv is None else argv, on_parent_exit=_orphan_cleanup_lazy
        )
    except Exception:
        return False


def _no_raise(fn: Callable[[], object]) -> Callable[[], None]:
    def run() -> None:
        with contextlib.suppress(Exception):
            fn()

    return run


def armed_target(
    gui_pid: int, purpose: str, target: Callable[..., object], *args: object
) -> None:
    """Cible de Process : arme le chien de garde GUI dans le point d'entrée réel
    de l'enfant, puis exécute ``target``. Nettoyage driver borné à la sortie.

    Aucune exception ne sort d'ici : en exe fenêtré, ``sys.stderr`` vaut None et
    multiprocessing lèverait AttributeError en l'imprimant ; le chargeur afficherait
    alors une boîte modale « Unhandled exception in script » qui fige le processus
    (handle WinDivert/SCM et dossier _MEI retenus). L'erreur est journalisée, puis
    sortie avec un code entier (fail-open : handle fermé, trafic non détourné)."""
    with contextlib.suppress(Exception):
        from util.driver import orphan_cleanup

        arm_with_pid(gui_pid, purpose, on_exit=orphan_cleanup)
    try:
        target(*args)
    except BaseException as exc:
        if isinstance(exc, SystemExit) and isinstance(exc.code, int | None):
            raise
        ci_traceback(f"target {purpose}")  # diagnostic CI seulement
        if is_shutdown_read_error(exc) and _orphan_requested_recently():
            # GUI disparue : WinDivertShutdown (demandé juste avant) a interrompu la
            # lecture -> WinError 232, attendu. Toute autre erreur : journalisée.
            logging.getLogger("debugger").info(
                "%s: capture stopped after GUI exit (%s)", purpose, type(exc).__name__
            )
            return
        logging.getLogger("debugger").exception(
            "%s: unhandled exception, worker exits (fail-open)", purpose
        )
        raise SystemExit(1) from None
    finally:
        if _orphan_requested():
            _wait_orphan(WORKER_CLEANUP_S)  # fermeture de NOTRE handle terminée


ERROR_NO_DATA = 232  # « The pipe is being closed » : recv après WinDivertShutdown


def is_shutdown_read_error(exc: BaseException) -> bool:
    """Erreur de lecture WinDivert attendue après WinDivertShutdown (WinError 232)."""
    if not isinstance(exc, OSError):
        return False
    code = getattr(exc, "winerror", None)
    if code is None:  # hors Windows (tests) : errno porte le code
        code = exc.errno
    return code == ERROR_NO_DATA


def _orphan_requested_recently() -> bool:
    try:
        from util.driver import orphan_shutdown_requested_within

        return orphan_shutdown_requested_within()
    except Exception:
        return False


def _orphan_requested() -> bool:
    try:
        from util.driver import orphan_shutdown_requested

        return orphan_shutdown_requested()
    except Exception:
        return False


def _wait_orphan(timeout: float) -> None:
    with contextlib.suppress(Exception):
        from util.driver import wait_orphan_cleanup

        wait_orphan_cleanup(timeout)


def _sentinel_cleanup(owned: Any) -> Callable[[], object]:
    def run() -> object:
        from util.driver import OWNED_ENV, orphan_cleanup

        if owned.value:  # n'agit que si Guardian a chargé le pilote
            os.environ[OWNED_ENV] = "1"
        return orphan_cleanup()

    return run


def driver_sentinel(gui_pid: int, owned: Any, ready: Any) -> None:
    """Processus sentinelle armé AVANT le chargement du pilote : si la GUI meurt,
    nettoyage borné (désenregistrement seulement si Guardian possède le pilote)."""
    arm_with_pid(gui_pid, "driver sentinel", on_exit=_sentinel_cleanup(owned))
    ready.set()
    while True:
        time.sleep(3600)


def start_driver_sentinel(timeout: float = 15.0) -> Any:
    """Lance la sentinelle et attend qu'elle soit armée. Retourne la valeur
    partagée ``owned`` (à mettre à 1 après chargement), ou None. Fail-open."""
    try:
        import multiprocessing as mp

        owned = mp.Value("b", 0, lock=False)
        ready = mp.Event()
        proc = mp.Process(
            target=driver_sentinel,
            args=(os.getpid(), owned, ready),
            name="guardian-driver-sentinel",
            daemon=True,
        )
        proc.start()
        log_spawn("driver sentinel", proc.pid)
        if not ready.wait(timeout):
            ci_diag("driver sentinel not armed in time (fail-open)")
        return owned
    except Exception:
        logging.getLogger("debugger").exception("driver sentinel failed")
        return None


# -- point d'entrée des enfants multiprocessing (exe fenêtré) ----------------------
FORK_FLAG = "--multiprocessing-fork"


def run_freeze_support(
    freeze: Callable[[], object],
    argv: list[str],
    hard_exit: Callable[[int], object] = os._exit,
) -> None:
    """``freeze_support`` sans boîte « Unhandled exception in script » (audit B1).

    Uniquement si ``--multiprocessing-fork`` est dans ``argv`` ET que l'exception
    n'est pas un SystemExit de code 0/None : traceback dans ci-crash.log (sonde CI
    uniquement), journal discret, puis ``os._exit(1)`` sans relancer (p. ex.
    spawn_main : WinError 5 quand la GUI parente vient d'être tuée). Dans tous les
    autres cas (GUI, sortie normale 0/None) : exception relancée."""
    try:
        freeze()
    except BaseException as exc:
        normal = isinstance(exc, SystemExit) and exc.code in (0, None)
        if FORK_FLAG not in argv or normal:
            if not normal:
                ci_traceback("freeze_support")
            raise
        ci_traceback("multiprocessing child (freeze_support)")
        with contextlib.suppress(Exception):
            logging.getLogger("debugger").info(
                "multiprocessing child failed, exit 1 (parent gone?): %s: %s",
                type(exc).__name__,
                exc,
            )
            logging.shutdown()
        hard_exit(1)


auto_arm()
