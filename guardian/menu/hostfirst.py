"""Affichage de la « Session publique en hôte au départ » (compte à rebours)."""

from __future__ import annotations

import time
from typing import Any

from network.sessions import HostFirstSession
from util.console import get_original_console_title, set_console_title
from util.i18n import t


def host_first_countdown(
    session: HostFirstSession,
    sleep: Any = time.sleep,
    out: Any = print,
    set_title: Any = set_console_title,
) -> None:
    """Compte à rebours de la phase 1, puis message « Session ouverte »."""
    while not session.is_open():
        out(t("host_first.countdown", s=int(session.remaining() + 0.999)), end="\r")
        sleep(min(1.0, max(0.05, session.remaining())))
    out(" " * 60, end="\r")
    out(t("host_first.opened"))
    # Le filtre a fini son travail : titre de console d'origine.
    set_title(get_original_console_title())
