"""Alerte sonore : winsound sous Windows, sans effet ailleurs. Ne lève jamais."""

from __future__ import annotations

import logging
import sys

logger = logging.getLogger(__name__)


def beep() -> bool:
    """Bip système asynchrone (MessageBeep) ; renvoie True si joué."""
    if sys.platform != "win32":
        return False
    try:
        import winsound

        winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        return True
    except Exception:
        logger.debug("alerte sonore impossible", exc_info=True)
        return False
