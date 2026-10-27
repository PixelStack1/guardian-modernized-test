"""Réglage « relais Rockstar » : autoriser (par défaut, comportement v3.6.1) ou bloquer.

Guardian ne distingue pas de « relais » à part : le trafic relayé par Rockstar passe par
les plages officielles Take-Two/Rockstar (AS202021, AS46555 ; util/dynamicblacklist.py),
reconnues par ``menu.livesession.is_rockstar_server``. Ce réglage s'applique donc à
TOUTE cette catégorie « serveur Rockstar » dans la vue Session en direct :

- « autoriser » : rien ne change (jamais bloqué, jamais compté comme joueur) ;
- « bloquer » : les paquets de/vers ces IP sont simplement jetés (jamais modifiés,
  aucun paquet fabriqué). Vous risquez de perdre la session : choix explicite.

Persisté dans data.json (clé ``rockstar_relay``). Aucune lecture du jeu, aucun réseau.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

RELAY_KEY = "rockstar_relay"
RELAY_ALLOW = "autoriser"
RELAY_BLOCK = "bloquer"
RELAY_VALUES = (RELAY_ALLOW, RELAY_BLOCK)
RELAY_DEFAULT = RELAY_ALLOW


def normalize(value: Any) -> str:
    """Valeur inconnue/absente/invalide = « autoriser » (fail-safe : comportement actuel)."""
    if isinstance(value, str) and value.strip().lower() in RELAY_VALUES:
        return value.strip().lower()
    return RELAY_DEFAULT


def load_mode(data: Mapping[str, Any]) -> str:
    try:
        return normalize(data.get(RELAY_KEY, RELAY_DEFAULT))
    except Exception:
        return RELAY_DEFAULT


def is_block(mode: str) -> bool:
    return normalize(mode) == RELAY_BLOCK


def toggled(mode: str) -> str:
    return RELAY_ALLOW if is_block(mode) else RELAY_BLOCK
