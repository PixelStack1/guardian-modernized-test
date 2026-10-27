# Changelog

## Non publié — Lot 7 (extras)

- Amis : jamais jetés par la capture (même bloqués, en panique ou verrou), blocage manuel refusé, ignorés par le bouclier auto, retirés des blocages chargés au démarrage. Page « Amis » traduite (i18n).
- Profils en un clic Solo / Entre amis / Publique (préréglages des bascules existantes, sauvegardés dans data.json).
- Raccourcis globaux Windows (RegisterHotKey) : Ctrl+Alt+F12 arrêt d'urgence, Ctrl+Alt+X panique, Ctrl+Alt+A/T/V bouclier/blocage total/verrou.
- Arrêt d'urgence : la capture laisse tout passer (`w.send(packet)` seul), blocages en mémoire levés, modes de rejet coupés ; fichiers inchangés, reprise = blocages enregistrés rétablis.
- Arrêt propre du pilote : session en fond fermée avant le service WinDivert, aussi sur fermeture de console / déconnexion / arrêt (SetConsoleCtrlHandler) et aboutToQuit.
- Diagnostic au démarrage (admin, WinDivert intègre, data.json lisible) et SHA256 de l'exécutable dans les Réglages.

## Non publié — Lot 5 (interface, alignement maquette)

- Interface PySide6 recalée sur la maquette `guardian-ui-mockup` : barre latérale 220 px (marque, navigation 39 px, sélecteur FR/EN, état du pilote), cartes de bascule 83 px, statistiques 64 px, tableau 37 px par ligne avec drapeaux, badges et mini-barres, panneau d'alertes 280 px avec pastille colorée et horodatage, pied de page 22 px.
- Réglages en grille 3×3 (curseurs, puces pays, contrôles segmentés).
- Noms de pays sur une ligne (points de suspension).
- `tools/compare_mockup.py` génère les comparaisons côte à côte dans `docs/compare/`.
- Aucun changement de la logique réseau.

## Non publié — Lot 3 (filtres d'information)

- Pays : FR, BE, CH, CA (+ `trusted_countries` de data.json) jamais bloqués ; autres pays
  signalés seulement (badge `PAYS`). Base hors ligne existante (sapics geo-whois-asn-country, CC0).
- Ping estimé passif (best-effort, `ping_max_ms`, défaut 150 ms) : signalement seul.
- Débit par joueur : alerte à 60 paquets/s entrants par IP (`rate_limit_pps`).
- Badge VPN/hébergeur : liste locale (sapics origin-asn, PDDL-1.0, tools/build_vpn.py) ;
  `vpn_flag` ON, `vpn_auto_block` OFF par défaut.
- Correctifs d'audit : F1 `seen_overflow` (verrou fail-safe + alerte « liste pleine »),
  F2 caractères non imprimables retirés, F3 recidivistes.json > 2 Mo ignoré,
  F4 repli `~/AppData/Local/Guardian`, F5 rotation supprime les `.tmp-*.csv` périmés.
- Rejeu : `--filtres`, `--vpn-blocage`.

## 3.6.1

- Session en direct : mots d'état ACTIVÉ/désactivé (ON/off) en vert/rouge pour le bouclier auto,
  l'enregistrement et le blocage total.
- Suppression des mentions « version de test » (titre de la vue, menu, README).
- README mis à jour (FR/EN) avec l'ensemble des fonctions.

## 3.6.0

- Session en direct : IP connectées avec pays, paquets/s et tailles ; détection de rafales
  (orange/rouge).
- Bouclier auto (désactivé par défaut, IP rouges, 7 jours, `D` pour lever).
- Blocage total (10 min, coupe aussi l'envoi ; pas un kick garanti).
- Blocage/déblocage manuel et pseudo ; rapports d'incident automatiques.
- Serveurs Rockstar reconnus et affichés à part, jamais comptés ni bloqués.
- `[R]etour` garde la protection active en arrière-plan, `[Q]` l'arrête.
- Mode enregistrement (métadonnées seulement), langue FR/EN, session publique en hôte au départ.

## Lot 5 — Interface graphique (PySide6)
- Fenêtre native PySide6 par défaut (sans console) ; `--console` garde l'interface texte.
- Toutes les touches de la vue en direct accessibles (boutons + raccourcis identiques), réglages data.json éditables.
- La GUI lit un instantané via QTimer (500 ms) ; la capture WinDivert reste dans son processus.
