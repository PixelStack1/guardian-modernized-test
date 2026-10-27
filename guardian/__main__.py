import contextlib
import ctypes
import logging
import sys
from multiprocessing import freeze_support

import pydivert

from network.sessions import FilterOpenError, extra_ports_enabled, probe_filter
from util.console import attach_console
from util.crash import crash_report
from util.driver import DriverLifecycle
from util.i18n import t
from util.integrity import IntegrityError, secure_windivert
from util.paths import data_file
from util.printer import print_white
from util.version import __version__

logger = logging.getLogger(__name__)
logger.propagate = False
logger.setLevel(logging.INFO)
if not logger.handlers:
    fh = logging.FileHandler(filename=data_file("history.log"))
    fh.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "[%(asctime)s][%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    fh.setFormatter(formatter)
    logger.addHandler(fh)

debug_logger = logging.getLogger("debugger")
debug_logger.setLevel(logging.DEBUG)
if not debug_logger.handlers:
    fh = logging.FileHandler(data_file("debugger.log"))
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(
        logging.Formatter(
            "[%(asctime)s][%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    debug_logger.addHandler(fh)


CONSOLE_MODE = "--console" in sys.argv


def gui_mode(argv: list[str]) -> bool:
    """GUI par défaut (lot 5) ; ``--console`` garde l'ancienne interface texte."""
    return "--console" not in argv and "--self-test-exit" not in argv


def close_splash() -> None:
    """Ferme l'écran de démarrage PyInstaller (exe gelé uniquement)."""
    with contextlib.suppress(Exception):
        import importlib

        importlib.import_module("pyi_splash").close()


def notify(text: str, console: bool | None = None) -> None:
    """Message utilisateur affiché UNE seule fois : console en mode ``--console``,
    sinon boîte de dialogue Windows (repli console si elle échoue)."""
    console = CONSOLE_MODE if console is None else console
    if not console:
        close_splash()
        try:
            ctypes.windll.user32.MessageBoxW(0, text, "Guardian", 0x10)
            return
        except Exception:
            pass
    if sys.stdout is not None:
        print_white(text)


if __name__ == "__main__":
    freeze_support()
    if CONSOLE_MODE:
        # Exécutable fenêtré (sans console) : en ouvrir une pour --console.
        attach_console()

    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            notify(t("main.need_admin"))
            logger.info("Started without admin")
            if CONSOLE_MODE:
                input(t("main.press_enter"))
            sys.exit()
        if CONSOLE_MODE:
            print_white(t("main.init"))
        try:
            hashes = secure_windivert()
        except IntegrityError as e:
            notify(t("main.integrity", e=e))
            logger.error("WinDivert integrity check failed: %s", e)
            sys.exit(3)
        logger.info("WinDivert binaries verified: %s", hashes)
        driver = DriverLifecycle(pydivert.WinDivert)
        driver.start()
        # Lot 7 : notre handle (session en fond) est fermé AVANT le pilote, et le
        # nettoyage couvre aussi fermeture de console / déconnexion / arrêt.
        from menu.livesession import stop_background

        driver.add_pre_cleanup(stop_background)
        driver.install_console_handler()
        # Onefile: si le bootloader parent est tué seul, l'enfant libère le pilote et sort.
        from util import parentwatch

        if parentwatch.is_onefile_child():
            probe = parentwatch.windows_parent_probe()
            if probe is not None:
                parentwatch.start_parent_watchdog(probe, driver.cleanup)
        try:
            probe_filter(extra_ports_enabled())
        except FilterOpenError as e:
            notify(t("main.filter_failed", e=e))
            logger.error("WinDivert filter open failed: %s", e)
            driver.cleanup()
            sys.exit(4)
        ctypes.windll.kernel32.SetConsoleTitleW(f"Guardian {__version__}")
    except Exception as e:
        crash_report(e, "Guardian crashed before reaching main()")
        raise

    try:
        if "--self-test-exit" in sys.argv:
            # Non-interactive quit path used by CI: initialise (driver loaded), then exit normally.
            close_splash()
            print_white(t("main.self_test"))
        elif gui_mode(sys.argv):
            from gui.app import run_gui

            run_gui(version=__version__, on_shutdown=driver.cleanup)
        else:
            close_splash()
            # Import tardif : menu.menu télécharge les plages Azure à l'import ;
            # en mode GUI, cela se fait derrière la fenêtre de démarrage.
            from menu.menu import Menu

            Menu.main_menu()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        crash_report(e, "Guardian crashed in main()")
        raise
    finally:
        driver.cleanup()
