"""Affichage de la « Session publique en hôte au départ » (compte à rebours)."""

from __future__ import annotations

import contextlib
import math
import time
from typing import Any

from network.sessions import (
    HOST_FIRST_FAILED,
    HOST_FIRST_SECONDS,
    HOST_FIRST_STARTED,
    HostFirstSession,
)
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


class FilterStartFailed(Exception):
    """Le processus de filtrage est mort ou n'a pas pu ouvrir WinDivert."""


def valid_duration(value: Any) -> float | None:
    """Durée annoncée acceptée seulement si finie et dans ]0, HOST_FIRST_SECONDS]."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    d = float(value)
    if math.isfinite(d) and 0 < d <= HOST_FIRST_SECONDS:
        return d
    return None


def _dead_reason(conn: Any) -> str:
    """Processus mort : récupère un éventuel (HOST_FIRST_FAILED, raison) en attente."""
    try:
        while conn.poll(0):
            msg = conn.recv()
            if isinstance(msg, tuple) and len(msg) == 2 and msg[0] == HOST_FIRST_FAILED:
                return str(msg[1])
    except Exception:
        pass
    return "process not alive"


def wait_until_started(
    session: HostFirstSession,
    conn: Any,
    timeout: float = START_TIMEOUT_SECONDS,
    clock: Any = time.monotonic,
    is_alive: Any = None,
) -> bool:
    """Attend le message HOST_FIRST_STARTED du processus de filtrage (au plus ``timeout`` s).
    Reçu : l'échéance locale est recalée sur la durée annoncée (si valide). Sinon : on
    démarre quand même. Lève FilterStartFailed si le processus meurt (``is_alive``) ou
    signale un échec d'ouverture (HOST_FIRST_FAILED)."""
    deadline = clock() + timeout
    while True:
        if is_alive is not None and not is_alive():
            raise FilterStartFailed(_dead_reason(conn))
        left = deadline - clock()
        if left <= 0:
            break
        try:
            if not conn.poll(min(left, 0.25)):
                continue
            msg = conn.recv()
        except Exception:
            break
        if isinstance(msg, tuple) and len(msg) == 2 and msg[0] == HOST_FIRST_FAILED:
            raise FilterStartFailed(str(msg[1]))
        if isinstance(msg, tuple) and len(msg) == 2 and msg[0] == HOST_FIRST_STARTED:
            duration = valid_duration(msg[1])
            if duration is None:
                duration = session.duration
            session.open_at = session.clock() + duration
            return True
    if is_alive is not None and not is_alive():
        raise FilterStartFailed(_dead_reason(conn))
    session.open_at = session.clock() + session.duration
    return False
