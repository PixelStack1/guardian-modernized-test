# Changelog

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
