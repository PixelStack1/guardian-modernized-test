"""Réglage « relais Rockstar » : autoriser (par défaut, comportement v3.6.1) ou bloquer.

Les IP Rockstar sont reconnues par les plages officielles Take-Two/Rockstar
(AS202021, AS46555 ; util/dynamicblacklist.py, ``menu.livesession.is_rockstar_server``).
Ces plages hébergent À LA FOIS les serveurs relais (jeu P2P relayé) et les services
(authentification, Social Club, matchmaking). Heuristique « relais » (``is_relay_traffic``),
TOUTES les conditions sont requises :

1. IP Rockstar ;
2. UDP (l'authentification / Social Club / HTTPS sont en TCP : jamais concernés) ;
3. port de jeu 6672 exactement (61455-61458, ports de services documentés, exclus) ;
4. taille de charge utile hors des tailles connues de heartbeat / matchmaking
   (``PROTECTED_SIZES`` : KNOWN_SIZES de network/sessions.py + réponses 45/125/205) ;
   taille inconnue = protégé.

- « autoriser » : rien ne change (jamais bloqué, jamais compté comme joueur) ;
- « bloquer » : seuls les paquets « relais » ainsi définis sont simplement jetés
  (jamais modifiés, aucun paquet fabriqué). Tout le reste passe.

Limite : c'est une heuristique de métadonnées (protocole, port, taille), pas une
identification certaine. Un futur message de matchmaking d'une taille nouvelle sur 6672
serait traité comme relais ; à l'inverse, du jeu relayé de taille « connue » passe.

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


GAME_PORT = 6672
# Tailles de heartbeat + matchmaking (copie de network/sessions.py KNOWN_SIZES, que l'on
# n'importe pas ici car sessions.py dépend de Windows ; inclusion vérifiée par les tests),
# plus les tailles de RÉPONSE de matchmaking suspectées (commentaire de sessions.py :
# 45, 125, 205) : par prudence elles ne sont jamais jetées.
HEARTBEAT_SIZES = frozenset({12, 18, 63})
MATCHMAKING_SIZES = frozenset({191, 207, 223, 239})
MATCHMAKING_RESPONSE_SIZES = frozenset({45, 125, 205})
PROTECTED_SIZES = HEARTBEAT_SIZES | MATCHMAKING_SIZES | MATCHMAKING_RESPONSE_SIZES


def is_relay_traffic(udp: bool, game_port: int | None, size: int | None) -> bool:
    """Vrai seulement pour du trafic de jeu UDP 6672 hors heartbeat/matchmaking.
    L'appelant vérifie en plus que l'IP est Rockstar. Dans le doute : False."""
    try:
        return (
            bool(udp)
            and game_port == GAME_PORT
            and size is not None
            and int(size) >= 0
            and int(size) not in PROTECTED_SIZES
        )
    except Exception:
        return False
