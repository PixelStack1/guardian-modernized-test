# Guardian

Custom firewall for the game GTA Online (version 1.66 and onwards).

[![Latest release](https://img.shields.io/github/v/release/TheMythologist/guardian)](https://github.com/TheMythologist/guardian/releases/latest)
[![CI status](https://github.com/TheMythologist/guardian/workflows/build/badge.svg)](https://github.com/TheMythologist/guardian/actions?query=branch%3Amain)
[![Downloads](https://img.shields.io/github/downloads/TheMythologist/guardian/total)](https://github.com/TheMythologist/guardian/releases)
[![License](https://img.shields.io/github/license/TheMythologist/guardian)](LICENSE)

## Guardian 3.6.1 — ce que fait Guardian (Français)

Guardian est un pare-feu pour GTA Online sur Windows. Il s'appuie sur le pilote **WinDivert** et se
contente de **laisser passer ou jeter des paquets** : il ne lit ni ne modifie jamais le jeu, et ne
fabrique ni n'envoie jamais de paquets.

- **Modes de session** : session solo, liste blanche, liste noire, liste blanche automatique,
  session verrouillée, **session vide (forcer l'hôte)** et **session publique en hôte au départ**
  (60 s fermée pour devenir hôte, puis ouverture automatique).
- **Session en direct** : liste des IP connectées avec pays (drapeau), paquets/s, octets/s, taille
  moyenne et maximale des paquets. Une rafale anormale colore la ligne en **orange** (inhabituel)
  puis en **rouge** (suspect). L'état ACTIVÉ/désactivé des options s'affiche en vert/rouge.
- **Bouclier auto** (désactivé par défaut, touche `A`) : bloque automatiquement pendant **7 jours**
  les seules IP au niveau rouge. `D` débloque à tout moment.
- **Blocage total** (désactivé par défaut, touche `T`) : quand une IP est bloquée, coupe **aussi
  l'envoi** vers elle pendant **10 minutes**. ⚠️ Ce n'est **pas un kick garanti** : cela coupe
  seulement le lien entre toi et ce joueur, et si ce joueur est l'hôte, c'est toi qui peux sortir.
- **Bloquer / Débloquer à la main** (`B` / `D`) et **pseudo** (`P`) pour nommer une IP.
- **Rapports d'incident automatiques** dans `%LOCALAPPDATA%\Guardian\rapports\` à chaque blocage :
  IP, pays, heure, ce qu'elle a envoyé (débits, tailles, type d'anomalie), prêts à transmettre à
  Rockstar. Une IP n'identifie pas un compte et ne garantit aucun ban.
- **Serveurs Rockstar reconnus** : affichés à part (en cyan), jamais comptés comme joueurs et
  jamais bloqués.
- **`[R]etour`** revient au menu en laissant la protection active en arrière-plan ;
  **`[Q]uitter`** l'arrête.
- **Mode enregistrement** (`E`) pour régler les seuils : uniquement des métadonnées (heure, IP,
  taille, sens), jamais le contenu des paquets.
- **Langue** : Français (par défaut) ou English, depuis le menu.

Guardian est basé sur le Guardian original de **Speyedr** et de ses contributeurs (dont
TheMythologist), distribué sous licence **LGPL** (voir [LICENSE](LICENSE)). Historique : [CHANGELOG](CHANGELOG.md).

## Guardian 3.6.1 — what Guardian does (English)

Guardian is a firewall for GTA Online on Windows, built on the **WinDivert** driver. It only
**lets packets through or drops them**: it never reads or modifies the game, and never crafts or
sends packets.

- **Session modes**: solo, whitelisted, blacklisted, auto-whitelisted, locked, **empty session
  (force host)** and **public session, host first** (closed 60 s so you become host, then opens).
- **Live session**: connected IPs with country (flag), packets/s, bytes/s, average and max packet
  size. Abnormal bursts turn the row **orange** (unusual) then **red** (suspicious). ON/off
  states are shown in green/red.
- **Auto shield** (off by default, `A`): blocks red-level IPs only, for **7 days**. `D` unblocks.
  Absolute rate rule (`shield_pps` default 80, `shield_seconds` default 5, in `data.json`): an IP turns
  red when it averages more than `shield_pps` pkt/s over `shield_seconds` (**more than 400 packets in
  5 s** by default), with at least N-1 of the last N one-second slices (N = ceil(`shield_seconds`),
  min 3) each above **75 %** of the limit, and the IP seen for at least `shield_seconds`. It is also
  cut on a **flood** (average above 3x the limit) or when its 8192-timestamp memory fills up after
  at least 1 s. A short dip does not reset the count. A burst starting from a low rate is cut after
  **about 4 s at least** (3 to 5 s); an IP already at 79-80 pkt/s that ramps up may be cut faster,
  by design; a very strong flood is cut too. Friends, the whitelist, Rockstar/Take-Two and Azure
  are never cut.
- **Total block** (off by default, `T`): when an IP is blocked, also cuts **outgoing** traffic to
  it for **10 minutes**. ⚠️ **Not a guaranteed kick**; if that player is host, you may be the one
  who leaves.
- Manual **Block / Unblock** (`B` / `D`) and **nickname** (`P`).
- **Automatic incident reports** in `%LOCALAPPDATA%\Guardian\rapports\` (IP, country, time, what it
  sent), ready to send to Rockstar. An IP does not identify an account nor guarantee a ban.
- **Rockstar servers recognised**: shown separately, never counted as players, never blocked.
- **`[R]`** returns to the menu with protection still running in the background; **`[Q]`** stops it.
- **Recording mode** (`E`) for tuning: metadata only (time, IP, size, direction), never packet content.
- **Language**: French (default) or English.

Based on the original Guardian by **Speyedr** and contributors (including TheMythologist), LGPL.

## [Download the latest version](https://github.com/TheMythologist/guardian/releases/latest)

### Requirements

- Windows 10/11 64-bit (WinDivert 2.2 via pydivert 4.x)
- Administrator Privileges

## How to use

1. Download the latest version from the [releases](https://github.com/TheMythologist/guardian/releases)
2. Run `Guardian.exe` (you will be prompted to run as Administrator)
3. Start a **Solo Session** with Guardian
4. Launch GTA online and enjoy 🎉
   - If you want to let your friends in, add their IP addresses into the `Whitelist` and use a **Whitelisted Session** instead.
5. If you don't know your friends' IPs, you'll have to stop the **Solo Session** and tell them to join as quick as possible.
   - Note that the session is vulnerable to randoms during this time.
6. Once your friends are loading into your session (they've confirmed they want to join your session and are now in the clouds), start a **Locked Session**.
   - While a session is Locked, no one will be able to join the session, but those already connecting / connected should remain.

Guardian *may* work in other circumstances/setups, but is less likely to produce secure sessions.

## How it works

Guardian intercepts all incoming GTA traffic, and only allows specific packets through depending on the configuration. GTA service-related packets are still allowed so you can communicate with GTA servers, but other players will not be able to join your session (unless you specify their IP addresses in the whitelist configuration).

By observing network activity while playing GTA Online, it is discovered that the "type" of packet can be determined based on the packet's payload size even though they are encrypted. Other than user-defined configuration, the only other behaviours intended to be allowed through are the session "heartbeat" and any session information requests from the "matchmaking service" which provides initial connection details to clients.

## Session Types

Guardian has many different kinds of sessions, each with different behaviours intended to be used under different circumstances.

The most important requirement for securing a session with Guardian is that you are the **"session host"**. You can still use Guardian to block packets as a non-host player, but improper use of session types as a non-host will likely get you disconnected from the session.

- *Solo Session*
  - The strictest firewall, intended for use when you plan to only play by yourself. No one can connect to your game session, but critical R* related services and anything SocialClub related will still be let through. If you are in a session with any other player, they will lose connection to you.

- *Whitelisted Session*
  - Only IP addresses in your `Whitelist` will be allowed to connect to you. If you are the host of a session, anyone not in your whitelist will likely lose connection to the session. If you are not the host of your current session and other players in your current session are not on your whitelist (whether already in the session or joining sometime later), you will lose connection to everyone else when you enable this type of session. Ths is because your client will not be able to communicate with these players and you do not have host privileges to kick them out of the session.
  - Volontaire et repris du Guardian d'origine 3.5.0 : en mode Liste blanche, Guardian lit seulement quelques octets d'en-tête des paquets UDP chiffrés pour reconnaître les services Rockstar ; rien n'est enregistré ni affiché, et le jeu n'est pas lu. *(Intentional, from the original Guardian 3.5.0: in Whitelisted mode Guardian only reads a few header bytes of encrypted UDP packets to recognise Rockstar services; nothing is logged or shown, and the game is not read.)*

- *Blacklisted Session*
  - IP addresses in your `Blacklist` will not be allowed to connect to you. If a connection is routed through R\* servers, that connection will also be blocked as a security measure. This mode is *not recommended* as GTA Online has custom routing if only a handful of IP addresses are blocked.

- *Auto Whitelisted Session*
  - Similar to *Whitelisted Session*, but everybody in your current session is temporarily added to your whitelist, which prevents them from getting kicked. Any automatically collected IP addresses will be lost once the session ends, and there is (currently) no way to save them. Any connection that is believed to be a custom route (also known as a "Rockstar Tunnel") will be flagged, and you will be asked if you want to save these IPs to the temporary whitelist or not. If you do decide to save these IPs, players attempting to connect to you may be routed through these tunnels and may bypass your intended whitelist.

- *Locked Session*
  - This mode blocks all new connections, preventing new players from entering the session. Anyone already in the game session remains. This mode prevents people from entering the session through a "Rockstar Tunnel" while allowing anyone currently being tunnelled to remain in the game session. However, if a player leaves, they will not be able to join again. Enabling this mode as a non-host does not drop you from a session.

## Motivation

GTA Online on PC was too crazy with modders wreaking havoc and constantly spamming text messages or emails. They could also crash sessions, leak IPs, or even scrape R* IDs to join non-public sessions to continue harrassing people. Speyedr did some research and testing, and was eventually able to get Guardian to work again, and he publicly shared it with the open-source community (check out his repository [here](https://gitlab.com/Speyedr/guardian-fastload-fix)). I then decided to fork his own project and improve on the codebase further, as well as further improvements that I think the codebase can benefit from.

## Build from source

- Install Python 3.10+
- **(Recommended)** Use poetry.

  ```bash
  pip install poetry
  ```

- Install project dependencies via poetry from the top-level repo folder.

  ```bash
  poetry install
  ```

- Build the package from the top-level repo folder. The executable will be found in the `dist` directory.

  ```bash
  poetry run build
  ```

- Alternatively, you can run directly from the codebase without building

  ```bash
  poetry run python guardian
  ```

## Miscellaneous

- No reverse engineering of any R*-owned Intellectual Property was undertaken
- No decryption (nor any similar attack on encryption used to secure GTA Online) was performed to investigate packets
- I will not be held responsible for any misusing of this tool, including:
  - Getting banned by R* (unlikely to happen)
  - Still getting hacked/harrassed by modders despite using the tool

## Key differences in this fork

- Single executable binary
  - Just double-click and run!
- Able to change session type safely and securely with 0 downtime in-between
- Smaller package size
- Speed improvements
- UI overhaul
- Better developing experience (in my opinion, anyways)

## Developers

- [**TheMythologist**](https://github.com/TheMythologist)
- [**Speyedr**](https://gitlab.com/Speyedr/guardian-fastload-fix) (previous fork)
- [**DigitalArc Studio**](https://gitlab.com/digitalarc/guardian) (original fork)

## Support

- [**> Open an issue**](https://github.com/TheMythologist/guardian/issues/new)
- [**> Join Speyedr's Discord server**](https://discord.gg/6FzKCh4j4v)

## Notice

Modified version of Guardian by TheMythologist (https://github.com/TheMythologist/guardian), licensed under the GNU LGPL-3.0 (see LICENSE). Modifications (2026): see MODERNIZATION_NOTES.md.

## WinDivert driver lifecycle

Guardian loads the WinDivert driver only if it was not already registered, and unloads it
(`pydivert.WinDivert.unregister()`) on normal exit, Ctrl+C and best-effort via `atexit`.
A driver that was already loaded by another program is left untouched.
After a hard kill (Task Manager, power loss) cleanup cannot run; remove the driver manually
from an elevated prompt:

```
sc stop WinDivert
```

User data (`data.json`, `db.json`, `history.log`, `debugger.log`) is stored in
`%LOCALAPPDATA%\Guardian` (fallback `~/Guardian` on non-Windows; legacy files in the working directory are copied there once).

## Hardening

- **WinDivert integrity**: at startup Guardian hashes `WinDivert64.dll` and `WinDivert64.sys` from its own
  package directory and refuses to start unless they match the official basil00 WinDivert 2.2.2-A release
  (`c1e060ee…d7d9a2` / `8da08533…90ddc2`). The DLL is loaded by absolute path; the current directory is
  removed from the DLL search order.
- **Strict filter**: UDP to 6672 and 61455-61458 only. The extra ports can be disabled with
  `"extra_ports": false` in `%LOCALAPPDATA%\Guardian\data.json`. On 61455-61458 the payload-size
  heuristics (observed on 6672 only) are not used and Rockstar/Take-Two ranges are never blocked.
  These extra ports still need to be validated in real GTA Online sessions.
  If the filter cannot be opened, Guardian exits cleanly with a message.
- **IP lists**: the last good RIPE/Azure lists are cached; a new list that is empty, malformed or more than
  30% different from the previous one is rejected and the previous list is kept.

## Fermer le pilote WinDivert avant de jouer à un autre jeu en ligne / Closing the WinDivert driver before playing another online game

**Français**

- Le pilote WinDivert n'est chargé que pendant que Guardian tourne. Lors d'une fermeture normale
  (quitter, Ctrl+C), Guardian le décharge désormais automatiquement.
- Après un crash ou un arrêt forcé (Gestionnaire des tâches, coupure), il peut rester chargé jusqu'au redémarrage.
- **Vérifier** : ouvrir `cmd` **en tant qu'administrateur** puis taper `sc query WinDivert`.
  Si le service est absent (« FAILED 1060 »), le pilote n'est pas chargé.
- **Arrêter** : `sc stop WinDivert`, puis `sc query WinDivert` doit afficher `STOPPED` ou un service absent.
- **Le plus sûr** avant un jeu avec anti-triche noyau (Valorant/Vanguard, BattlEye, Easy Anti-Cheat) :
  redémarrer le PC, puis vérifier avec `sc query WinDivert`.

**English**

- The WinDivert driver is only loaded while Guardian runs. On a clean exit (quit, Ctrl+C), Guardian now
  unregisters it automatically.
- After a crash or a forced kill (Task Manager, power loss), it may stay loaded until you reboot.
- **Check**: open `cmd` **as administrator** and run `sc query WinDivert`.
  If the service is absent ("FAILED 1060"), the driver is not loaded.
- **Stop**: `sc stop WinDivert`, then `sc query WinDivert` should show `STOPPED` or an absent service.
- **Safest** before games with kernel anti-cheat (Valorant/Vanguard, BattlEye, Easy Anti-Cheat):
  reboot, then check with `sc query WinDivert`.

## Session publique en hôte au départ / Public session, host first

Entrée de menu « Session publique en hôte au départ » (EN : « Public session, host first »). Elle
n'est active que si tu la choisis dans le menu.

1. **Phase 1, 60 secondes fixes** (`HOST_FIRST_SECONDS` dans `guardian/network/sessions.py`, aucun
   réglage, aucune touche) : exactement le filtrage de la session solo (`SoloSession`) — les
   heartbeats et le trafic Rockstar/Take-Two sur les ports 61455-61458 passent, les demandes
   d'entrée (joins) sont jetées. Un compte à rebours s'affiche. Lance à ce moment une nouvelle
   session publique dans le jeu : seul, tu en deviens l'hôte.
2. **Phase 2** : au bout de 60 s, réouverture **automatique** (« Session ouverte ») : simple
   transfert, aucun join bloqué, comme une session publique normale ; le handle WinDivert est
   ensuite fermé. Pas de touche pour rouvrir plus tôt.

Uniquement du rejet pendant la phase 1 : aucun paquet n'est fabriqué, modifié ni envoyé, et le jeu
n'est ni lu ni modifié.

⚠️ **Guardian ne peut pas vérifier que tu es hôte** ; les **60 s sont une estimation** du temps
nécessaire pour créer la session. Une fois hôte, **les nouveaux joueurs qui arrivent ne te retirent
pas l'hôte** (l'hôte ne change que s'il quitte la session).

## Session en direct

**Français** — Menu principal → *Session en direct*.

- Tableau des pairs connectés : pays avec drapeau (ex. `🇫🇷 FR`, `—` si IP privée ou inconnue),
  heure de première apparition, paquets/s, octets/s, taille moyenne et max (fenêtre glissante de 3 s).
- La « normale » de chaque pair est apprise pendant ses 60 premières secondes. Ligne orange
  (« inhabituel ») puis rouge (« suspect ») en cas de rafale ciblée, de paquets énormes ou de longues
  séries de petits paquets identiques. Seuils : en tête de `guardian/network/anomaly.py`.
- **Bouclier auto** (IP rouges uniquement) : **désactivé par défaut**.
  À activer avec la touche `A` (ou `"auto_block_suspect": true` dans
  `%LOCALAPPDATA%\Guardian\data.json`). Il bloque l'IP **7 jours**
  et affiche `Bouclier auto : <ip> bloqué (rafale)`. Ces blocages sont **persistants** (ils survivent
  à un redémarrage) dans un fichier **séparé**, `%LOCALAPPDATA%\Guardian\auto_block.json`
  (IP + date d'expiration uniquement), jamais dans la liste noire de `data.json`. Ils **expirent
  tout seuls** (purge au chargement et en continu) et se lèvent avant terme avec `D`.
  ⚠️ Un innocent bloqué par erreur le reste **7 jours**, sauf déblocage manuel avec `D`.
  Il ne bloque **jamais** une IP de la liste blanche ni une plage Rockstar/Take-Two/Azure connue
  (filtre appliqué aussi au chargement du fichier). Si les plages Rockstar/Azure n'ont pas pu être
  chargées, le bouclier auto reste désactivé et les entrées du fichier ne sont pas appliquées.
  Les IP orange ne sont jamais bloquées automatiquement.
- **Règle de débit absolue du bouclier** (en plus de la règle x5, s'applique aussi pendant
  l'apprentissage), réglable dans `data.json` : `shield_pps` (défaut 80, borné 20–1000) et
  `shield_seconds` (défaut 5, borné 1–60). Une IP passe au rouge, et est donc coupée si le bouclier
  auto est actif, dans l'un de ces trois cas :
  - **règle normale** : plus de `shield_pps` paquets/s **en moyenne** sur les `shield_seconds`
    dernières secondes (par défaut **plus de 400 paquets en 5 s**), au moins N-1 des N dernières
    tranches d'1 s (N = `shield_seconds` arrondi au-dessus, minimum 3 ; 4 sur 5 par défaut) chacune
    au-dessus de **75 % du seuil** (plus de 60 paquets par défaut), et IP vue depuis au moins
    `shield_seconds` ;
  - **inondation** : plus de 3 × le seuil en moyenne sur la fenêtre (plus de 1200 paquets en 5 s),
    quel que soit le nombre de tranches ;
  - **saturation** : la mémoire par IP (8192 horodatages au plus) est pleine avant de couvrir la
    fenêtre, et l'IP est vue depuis au moins 1 s (un pic de 2 s sous ~4000 paquets/s ne la
    remplit pas).

  Une petite baisse ponctuelle ne remet pas le compteur à zéro. Une rafale partant d'un débit bas
  est coupée au bout d'**environ 4 s au minimum** (3 à 5 s selon sa force). Une IP déjà à 79-80
  paquets/s qui s'emballe peut être coupée **plus vite**, presque immédiatement : c'est voulu, sa
  moyenne sur 5 s dépasse déjà la limite. Une **inondation très forte** (plus de 1200 paquets en
  5 s) est coupée elle aussi, en général en moins de 1,5 s. Jamais pour les amis, la liste
  blanche, Rockstar/Take-Two ou Azure.
- **Bouclier manuel** (`B`) : bloque n'importe quelle IP choisie et l'écrit **de façon permanente**
  dans la liste noire de `data.json` (avec date et pseudo) ; `D` pour débloquer (retire aussi
  l'IP de la liste noire, ou de `auto_block.json` pour un blocage auto).
- **Blocage total** (touche `T`, ou `"total_block": true` dans `data.json`) : **désactivé par
  défaut**. Quand il est actif et qu'une IP est bloquée (bouclier auto rouge ou `B`), Guardian jette
  **aussi les paquets sortants** vers cette IP précise pendant **10 min** (`TOTAL_BLOCK_SECONDS`,
  en mémoire, jamais enregistré) ; ensuite seul le blocage entrant habituel continue (7 jours pour
  l'auto, permanent pour `B`). `D` lève aussi la coupure sortante. Repasser `T` à OFF lève **immédiatement toutes** les coupures sortantes en cours (le
  blocage entrant, lui, ne change pas : 7 jours pour l'auto, permanent pour `B`). Uniquement du rejet : aucun
  paquet n'est fabriqué, modifié ni envoyé au joueur ; en cas d'erreur, le paquet passe. Aucun
  trafic supplémentaire n'est capturé : le filtre reste le filtre strict (UDP vers 6672), tout
  le reste est réinjecté immédiatement. Mêmes garde-fous que le bouclier auto (jamais liste blanche,
  Rockstar/Take-Two ni Azure ; indisponible si les plages Rockstar/Azure n'ont pas pu être chargées).
  ⚠️ Cela coupe **seulement la liaison entre toi et ce joueur** ; ce n'est **pas un kick garanti**
  de toute la session, et **si ce joueur est l'hôte, c'est toi qui peux être éjecté**.
- Touches : `B` bloquer (immédiat + ajout à la liste noire avec date et pseudo), `P` pseudo,
  `D` débloquer, `A` bouclier auto, `T` blocage total, `E` enregistrement, `↑↓`/`+-` page, `R` retour au menu (la protection
  continue en arrière-plan), `Q` quitter (arrête la protection).
- Enregistrement : uniquement des métadonnées (horodatage, IP, taille, sens), jamais le contenu,
  dans `%LOCALAPPDATA%\Guardian\enregistrements\`. Nouveau fichier tous les 1 000 000 lignes /
  100 Mo, arrêt automatique après 5 fichiers.

### Relais Rockstar / Rockstar relay (touche L)

- **autoriser** (par défaut) : comportement inchangé. **bloquer** : jette UNIQUEMENT le jeu relayé
  par Rockstar, défini par l'heuristique suivante (toutes les conditions) : IP des plages officielles
  Rockstar/Take-Two + UDP + port de jeu 6672 (61455-61458 exclus) + taille hors heartbeat/matchmaking
  connus (12, 18, 63, 191, 207, 223, 239, et réponses 45, 125, 205). Authentification, Social Club,
  HTTPS (TCP) et matchmaking ne sont **jamais** jetés. Heuristique sur métadonnées, pas une certitude.
- EN: **allow** (default) keeps the current behavior; **block** drops only Rockstar-relayed UDP 6672
  game traffic (same rules), never auth / Social Club / HTTPS / matchmaking.

### Journal des nouveaux joueurs / New-player journal

Chaque nouvelle IP (hors serveurs Rockstar) : alerte dans la vue + ligne (heure, IP, pays local)
dans `%LOCALAPPDATA%\Guardian\journal\joueurs.log`. Rotation : 1 Mo par fichier, 1 fichier actif
+ 3 anciens, soit **au plus ~4 Mo sur le disque** (1 Mo × 4 fichiers). Aucun contenu de paquet.
EN: alert + log line per new IP; bounded to **~4 MB on disk** (1 MB × 4 files).

### Mode rejeu / Replay mode (QA, Linux)

`python -m guardian.replay <enregistrement.csv> [--relais bloquer] [--bouclier] [--lang en] [--journal DOSSIER]`
rejoue un enregistrement sans WinDivert et affiche les décisions. Les tests tournent aussi sans
`pydivert` installé (faux module minimal dans `tests/_fakes`, chargé seulement si besoin).

## Données hors ligne / Offline data

Aucun appel réseau à l'exécution. / No network calls at runtime.

- Pays / Country : `guardian/util/geoip_ipv4.bin.gz` — sapics/ip-location-db
  « geo-whois-asn-country », **CC0-1.0** (https://github.com/sapics/ip-location-db).
- VPN / hébergeurs / hosting : `guardian/util/vpn_ipv4.bin.gz` — sapics/ip-location-db
  « origin-asn », **PDDL-1.0**, instantané du 2026-10-27 (`util/vpn.py` : `SNAPSHOT`),
  liste d'AS dans `tools/build_vpn.py`. Indicatif seulement / indicative only.

Textes des licences / license texts : [`data-licenses/`](data-licenses/).

## Langue / Language

Menu principal → *Langue* : Français (par défaut) ou English. Réglage `"language": "fr"` / `"en"`
dans `data.json`. Traductions : `guardian/util/i18n.py`.

## Géolocalisation / Geolocation

Base hors ligne (aucun appel réseau) : [sapics/ip-location-db](https://github.com/sapics/ip-location-db),
jeu `geo-whois-asn-country` IPv4, licence **CC0-1.0** (domaine public). Fichier compact
`guardian/util/geoip_ipv4.bin.gz` (~1 Mo), régénérable avec `tools/build_geoip.py`. Pays approximatif.

### Rapports d'incident (automatiques)

À chaque blocage depuis la vue « Session en direct » (bouclier auto rouge **ou** touche B), Guardian écrit
immédiatement deux fichiers dans `%LOCALAPPDATA%\Guardian\rapports\` (`AAAAMMJJ-HHMMSS_<ip>.txt` et `.json`) :
identifiant court, début/fin avec fuseau, durée, version, IP source, ports observés, pays (pas d'ASN : aucune
base hors ligne fournie), type et niveau d'anomalie, paquets/s moyen et pic, totaux, taille max, référence
apprise vs observé, extrait de la fenêtre glissante, et un champ pseudo facultatif. Le .txt commence par un
en-tête prêt à coller pour Rockstar et rappelle qu'**une IP n'identifie pas un compte et ne garantit aucun ban**.
Un blocage manuel sans anomalie produit un rapport allégé. Les 200 derniers rapports sont conservés.
Écriture dans un thread dédié, hors capture ; aucune erreur disque ne peut interrompre la vue ; aucun appel réseau,
uniquement des métadonnées (jamais le contenu des paquets).

Si les plages Rockstar/Azure (`dynamic_blacklist`) n'ont pas pu être chargées, le bouclier auto reste désactivé
et la vue l'indique.
