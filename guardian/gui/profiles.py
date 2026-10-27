"""Profils en un clic (lot 7) : préréglages des bascules existantes.

Aucun nouveau mode de filtrage : chaque profil règle seulement panique, verrou,
bouclier auto, blocage total et coupure des récidivistes, comme les touches
X V A T C, avec les mêmes garde-fous et les mêmes sauvegardes dans data.json.
Les amis restent toujours autorisés (règle de la capture).
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass
from typing import Any

from menu import livesession as ls
from util.i18n import t

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Profile:
    key: str
    panic: bool
    session_lock: bool
    auto_block: bool
    total_block: bool
    offender_drop: bool

    def name(self) -> str:
        return t(f"profile.{self.key}")

    def description(self) -> str:
        return t(f"profile.{self.key}.desc")


PROFILES: dict[str, Profile] = {
    "solo": Profile("solo", True, False, True, True, True),
    "friends": Profile("friends", False, True, True, False, True),
    "public": Profile("public", False, False, True, False, True),
}


def current_profile(ctrl: Any) -> str | None:
    """Profil correspondant exactement à l'état courant, sinon None."""
    for p in PROFILES.values():
        with contextlib.suppress(Exception):
            if (
                bool(ctrl.panic) == p.panic
                and bool(ctrl.session_lock) == p.session_lock
                and bool(ctrl.auto_block)
                == (p.auto_block and ctrl.auto_block_available)
                and bool(ctrl.total_block)
                == (p.total_block and ctrl.auto_block_available)
                and bool(ctrl.offender_drop) == p.offender_drop
                and not getattr(ctrl, "filtering_paused", False)
            ):
                return p.key
    return None


def persist_toggles(config: Any, ctrl: Any) -> None:
    """Écrit dans data.json l'état courant des bascules persistées (cohérence)."""
    ls._save(config, ls.SESSION_LOCK_KEY, ctrl.session_lock)
    ls._save(config, ls.AUTO_BLOCK_KEY, ctrl.auto_block)
    ls._save(config, ls.TOTAL_BLOCK_KEY, ctrl.total_block)
    ls._save(config, ls.OFFENDER_DROP_KEY, ctrl.offender_drop)


def toggle_emergency(session: Any) -> bool:
    """Arrêt d'urgence / reprise. À la reprise, les bascules restaurées sont
    réécrites dans data.json (pendant l'arrêt, data.json n'est jamais modifié)."""
    with session.lock:
        ctrl = session.ctrl
        try:
            ctrl.toggle_emergency()
            if not ctrl.filtering_paused:
                persist_toggles(session.config, ctrl)
        except Exception:
            logger.exception("arrêt d'urgence impossible")
            return False
    return True


def apply_profile(session: Any, key: str) -> bool:
    """Applique le profil ``key`` à la session (sous son verrou). Faux si inconnu
    ou si l'arrêt d'urgence est actif."""
    p = PROFILES.get(key)
    if p is None:
        return False
    with session.lock:
        ctrl = session.ctrl
        config = session.config
        try:
            if getattr(ctrl, "filtering_paused", False):
                # Refusé : la reprise rétablirait l'instantané et écraserait le profil.
                ls.set_toggle_msg(ctrl, t("live.ev.paused_locked"))
                return False
            ctrl.panic = p.panic
            if bool(ctrl.session_lock) != p.session_lock:
                ctrl.toggle_session_lock()  # peut refuser (liste des IP vues pleine)
            ctrl.auto_block = p.auto_block and ctrl.auto_block_available
            ctrl.total_block = p.total_block and ctrl.auto_block_available
            ctrl.offender_drop = p.offender_drop
            persist_toggles(config, ctrl)
            ls.set_toggle_msg(ctrl, t("live.ev.profile", name=p.name()))
        except Exception:
            logger.exception("profil %r impossible", key)
            return False
    return True
