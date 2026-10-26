import ctypes
import logging
import sys
from multiprocessing import freeze_support

import pydivert

from menu.menu import Menu
from network.sessions import FilterOpenError, extra_ports_enabled, probe_filter
from util.crash import crash_report
from util.driver import DriverLifecycle
from util.i18n import t
from util.integrity import IntegrityError, secure_windivert
from util.paths import data_file
from util.printer import print_white

__version__ = "3.6.0"

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


if __name__ == "__main__":
    freeze_support()

    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print_white(t("main.need_admin"))
            logger.info("Started without admin")
            input(t("main.press_enter"))
            sys.exit()
        print_white(t("main.init"))
        try:
            hashes = secure_windivert()
        except IntegrityError as e:
            print_white(t("main.integrity", e=e))
            logger.error("WinDivert integrity check failed: %s", e)
            sys.exit(3)
        logger.info("WinDivert binaries verified: %s", hashes)
        driver = DriverLifecycle(pydivert.WinDivert)
        driver.start()
        try:
            probe_filter(extra_ports_enabled())
        except FilterOpenError as e:
            print_white(t("main.filter_failed", e=e))
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
            print_white(t("main.self_test"))
        else:
            Menu.main_menu()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        crash_report(e, "Guardian crashed in main()")
        raise
    finally:
        driver.cleanup()
