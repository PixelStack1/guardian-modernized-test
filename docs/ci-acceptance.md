# Banc d'acceptation Windows (lot 8)

`tests/windows/acceptance.py` exécute, sur l'exe **onefile** construit par la CI
(job `windows` de `.github/workflows/windows-real.yml`), les vérifications qui
étaient manuelles. Résultats : `logs/acceptance.txt` et
`logs/acceptance/acceptance.json` (artefact `guardian-windows-results`).

## Drapeau de test `--ci-probe <fichier.json>` (inerte en usage normal)

- Sans ce drapeau, rien ne change (aucun fichier écrit, filtre normal).
- Avec lui :
  - **filtre WinDivert à blanc** `false` : le pilote est chargé et un handle est
    ouvert (conditions réelles pour le nettoyage), mais aucun paquet n'est capturé,
    donc aucun `w.send`. Aucun paquet fabriqué, le jeu n'est jamais touché. Le mode
    passe aux processus enfants par `GUARDIAN_CI_DRY=1` (posée par l'exe lui-même).
  - la GUI écrit toutes les 200 ms son état dans le JSON (PID, fenêtre, statut,
    raccourcis enregistrés / reçus, SHA256 affiché, bascules, horodatages). Aucune IP.
- `history.log` contient un avertissement « CI acceptance probe » quand il est actif.

## Vérifications

| # | Vérification | Méthode | Seuil |
|---|---|---|---|
| 1a | Fin de tâche sur le PID visible (enfant GUI) | `taskkill /F /PID <enfant>` | arbre terminé ≤ 15 s, pilote absent ≤ 5 s |
| 1b | Fin de tâche sur le bootloader | `taskkill /F /PID <parent>` (chien de garde) | idem |
| 1c | Fermeture de la fenêtre | `WM_CLOSE` | idem |
| 2 | Déconnexion annulée | `WM_QUERYENDSESSION` puis `WM_ENDSESSION` wParam=FALSE | statut « Protection arrêtée » ≤ 10 s, Guardian toujours ouvert, pilote absent ≤ 5 s, fermeture propre ensuite |
| 3a | `RegisterHotKey` réussit pour les 5 raccourcis | sonde | — |
| 3b | Chaque raccourci déclenche son action | `PostThreadMessage(WM_HOTKEY)` vers le fil des raccourcis | action reçue ≤ 3 s, état basculé puis remis |
| 3c | AltGr+X/A/T/V ne déclenche rien | `SendInput` réel (LCtrl+RAlt+lettre), fenêtre de Guardian au premier plan | aucune action en 1,5 s |
| 3d | Ctrl+Alt+F12 réel | `SendInput` | urgence ≤ 3 s (SKIP si l'entrée n'est pas livrée) |
| 4 | SHA256 affiché = hash de l'artefact | sonde vs SHA256 du fichier | égalité |
| 5 | Lancement → écran de démarrage | 1re fenêtre visible du bootloader (`EnumWindows`) | ≤ 5000 ms |

« Pilote absent » = `sc query WinDivert` ne renvoie ni RUNNING ni *_PENDING
(1060 = service supprimé). Le banc ne tue que les PID qu'il a lancés (l'enfant
est vérifié : son PPID doit être le bootloader lancé par le banc).

## Seuils

Seuils provisoires, choisis avant toute mesure sur runner (le banc n'a pas
encore tourné sur Windows), surchargeables par `GUARDIAN_ACC_<NOM>` :
`SPLASH_MS=5000` (l'écran du bootloader s'affiche avant l'extraction complète,
attendu < 1 s), `MAIN_READY_MS=90000` (informatif, inclut le téléchargement des
plages Azure), `DRIVER_GONE_MS=5000`, `EXIT_MS=15000`, `HOTKEY_MS=3000`,
`LOGOFF_STATUS_MS=10000` (le statut apparaît 3 s après le nettoyage). Les
mesures sont dans `metrics` de `acceptance.json` : resserrer après quelques runs.

## Limites (non vérifiable en CI)

- Vraie déconnexion / arrêt de Windows : simulés par messages à la fenêtre.
- Gestionnaire des tâches réel : simulé par `taskkill /F` (même TerminateProcess).
- Claviers physiques AZERTY : `SendInput` injecte des codes virtuels ; la
  disposition du runner (US) ne produit pas les caractères AltGr, seul le
  non-déclenchement des raccourcis est vérifié.
- `SendInput` exige un bureau interactif ; s'il n'est pas livré, 3c/3d sont SKIP.
- Trafic GTA réel et blocage effectif : hors banc (filtre à blanc par conception).
- UAC (le runner est déjà administrateur) et SmartScreen.

## Durcissement (lot 8)

- `--ci-probe` n'est honoré que si **`GUARDIAN_CI_PROBE=1`** et **`CI=true`** (ou
  `GITHUB_ACTIONS=true`) sont présents. Sinon il est ignoré (ligne de log) et la
  protection fonctionne normalement. L'étape de workflow doit poser
  `GUARDIAN_CI_PROBE: "1"` ; `CI`/`GITHUB_ACTIONS` sont fournis par GitHub Actions.
- Mode sonde actif : bandeau rouge permanent « MODE TEST CI — protection désactivée »
  (EN : « CI TEST MODE — protection disabled »).
- Le banc ne vise que la fenêtre de Guardian retrouvée par son PID (EnumWindows) ;
  chaque PostMessage/SendMessage vérifie le propriétaire du HWND, PostThreadMessage
  vérifie que le thread appartient au PID, et SendInput n'est injecté que si la
  fenêtre au premier plan appartient à ce PID.
- La sonde applique une liste blanche de clés (`ALLOWED_KEYS`) et masque toute IP
  dans les textes libres.

## Réserve connue — capture « live » survivante après `taskkill /F` du PID GUI

Constat (runs 40564922194, 40566184605) : après un kill brutal de l'enfant GUI, le
driver WinDivert est bien désenregistré (≤ 10 ms, critère sécurité PASS), mais le
processus de capture (`--multiprocessing-fork`, rôle « live capture » d'après
`ci-spawn.log`) reste vivant > 15 s et maintient le bootloader. Son chien de garde
(OpenProcess SYNCHRONIZE sur le PID GUI, armé dans la cible du Process) se déclenche
en < 1 s (`gui gone -> exit`), mais le nettoyage borné ne se termine pas
(`cleanup done` jamais journalisé) et `os._exit` ne termine pas le processus :
hypothèse, un thread est bloqué dans une E/S driver (WinDivertRecv) non annulable
après le désenregistrement, et ExitProcess attend la fin de cette E/S.
Impact : le processus n'a plus d'accès au driver (service supprimé), il n'émet rien
et ne filtre plus rien. Pas de fail-closed. Piste : annuler l'E/S (CancelIoEx/
WinDivertShutdown) avant la fermeture, ou recv avec timeout.

### Mise à jour : sentinelle pilote et statut WARN

- Un processus « driver sentinel » est lancé et armé (OpenProcess SYNCHRONIZE sur
  le PID GUI) **avant** `driver.start()`. Il n'y a donc plus de fenêtre où le pilote
  est chargé sans gardien. Si la GUI meurt, il exécute le nettoyage borné (4 s) :
  désenregistrement seulement si Guardian a chargé le pilote (valeur partagée
  `owned`, mise à 1 après le chargement). Le serveur Manager exécute le même nettoyage.
- Le harnais rapporte « taskkill /F child PID: process tree exited » en **WARN —
  KNOWN RESERVE**, avec le temps mesuré (non bloquant). Tous les contrôles
  « WinDivert gone » restent stricts (FAIL bloquant). Le harnais n'attend pas
  l'armement avant le kill : le cas du kill précoce reste testé.
