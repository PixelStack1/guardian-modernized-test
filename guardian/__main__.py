import ctypes
import logging
import sys
from multiprocessing import freeze_support

import pydivert

from menu.menu import Menu
from util.crash import crash_report
from util.driver import DriverLifecycle
from util.printer import print_white

__version__ = "3.6.0.dev0"

logger = logging.getLogger(__name__)
logger.propagate = False
logger.setLevel(logging.INFO)
if not logger.handlers:
    fh = logging.FileHandler(filename="history.log")
    fh.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "[%(asctime)s][%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    fh.setFormatter(formatter)
    logger.addHandler(fh)

debug_logger = logging.getLogger("debugger")
debug_logger.setLevel(logging.DEBUG)
if not debug_logger.handlers:
    fh = logging.FileHandler("debugger.log")
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
            print_white("Please restart as administrator")
            logger.info("Started without admin")
            input("Press enter to exit.")
            sys.exit()
        print_white("Initialising...")
        driver = DriverLifecycle(pydivert.WinDivert)
        driver.start()
        ctypes.windll.kernel32.SetConsoleTitleW(f"Guardian {__version__}")
    except Exception as e:
        crash_report(e, "Guardian crashed before reaching main()")
        raise

    try:
        if "--self-test-exit" in sys.argv:
            # Non-interactive quit path used by CI: initialise (driver loaded), then exit normally.
            print_white("Self-test: initialised, exiting normally")
        else:
            Menu.main_menu()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        crash_report(e, "Guardian crashed in main()")
        raise
    finally:
        driver.cleanup()
