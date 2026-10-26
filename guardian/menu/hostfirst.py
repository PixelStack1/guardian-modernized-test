"""Affichage de la « Session publique en hôte au départ » (compte à rebours)."""

from __future__ import annotations

import contextlib
import time
from typing import Any

from network.sessions import HOST_FIRST_STARTED, HostFirstSession
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


# Attente maximale du signal « filtre lancé » avant de démarrer quand même le compte à rebours.
START_TIMEOUT_SECONDS = 10.0


def drain(conn: Any) -> None:
    """Vide les anciens messages du Pipe (ex. signaux d'autres filtres)."""
    with contextlib.suppress(Exception):
        while conn.poll(0):
            conn.recv()


def wait_until_started(
    session: HostFirstSession,
    conn: Any,
    timeout: float = START_TIMEOUT_SECONDS,
    clock: Any = time.monotonic,
) -> bool:
    """Attend le message HOST_FIRST_STARTED du processus de filtrage (au plus ``timeout`` s).
    Reçu : l'échéance locale est recalée sur la durée annoncée. Sinon : on démarre quand même."""
    deadline = clock() + timeout
    while True:
        left = deadline - clock()
        if left <= 0:
            break
        try:
            if not conn.poll(min(left, 0.25)):
                continue
            msg = conn.recv()
        except Exception:
            break
        if isinstance(msg, tuple) and len(msg) == 2 and msg[0] == HOST_FIRST_STARTED:
            try:
                duration = float(msg[1])
            except (TypeError, ValueError):
                duration = session.duration
            session.open_at = session.clock() + duration
            return True
    session.open_at = session.clock() + session.duration
    return False
