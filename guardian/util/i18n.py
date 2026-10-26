"""Traductions minimales FR/EN (dictionnaire simple, aucune dépendance).

Usage : ``from util.i18n import t`` puis ``t("cle", var=valeur)``.
Langue : réglage « language » de data.json (« fr » par défaut, ou « en »).
Pour traduire une nouvelle chaîne : ajouter une entrée dans STRINGS avec « fr » et
« en », puis remplacer le texte en dur par ``t("cle")``.
"""

from __future__ import annotations

from typing import Any

LANGUAGES = ("fr", "en")
DEFAULT_LANGUAGE = "fr"

_current: str | None = None

STRINGS: dict[str, dict[str, str]] = {
    # -- menu principal ---------------------------------------------------
    "menu.question": {"fr": "Que voulez-vous faire ?", "en": "What do you want?"},
    "menu.solo": {"fr": "Session solo", "en": "Solo Session"},
    "menu.whitelist": {"fr": "Session liste blanche", "en": "Whitelisted Session"},
    "menu.blacklist": {"fr": "Session liste noire", "en": "Blacklisted Session"},
    "menu.auto_whitelist": {
        "fr": "Session liste blanche automatique",
        "en": "Auto Whitelisted Session",
    },
    "menu.locked": {"fr": "Session verrouillée", "en": "Locked Session"},
    "menu.kick_unknowns": {"fr": "Expulser les inconnus", "en": "Kick unknowns"},
    "menu.new_session": {
        "fr": "Session vide (forcer l'hôte de session)",
        "en": "Empty Session (force Session Host)",
    },
    "menu.kick_by_ip": {"fr": "Expulser par IP", "en": "Kick by IP"},
    "menu.live": {"fr": "Session en direct (test)", "en": "Live session (test)"},
    "menu.edit_lists": {"fr": "Modifier les listes", "en": "Edit lists"},
    "menu.language": {"fr": "Langue : Français", "en": "Language: English"},
    "menu.discord": {"fr": "Discord de Speyedr", "en": "Speyedr's Discord"},
    "menu.quit": {"fr": "Quitter", "en": "Quit"},
    "menu.choose_language": {"fr": "Choisissez la langue", "en": "Choose the language"},
    "menu.opening_discord": {
        "fr": "Ouverture du lien Discord...",
        "en": "Opening Discord URL...",
    },
    # -- confirmation de session ----------------------------------------------
    "confirm.question": {
        "fr": "Type de session : {name}, êtes-vous sûr ?",
        "en": "Session type: {name}, are you sure?",
    },
    "confirm.yes": {"fr": "Oui, démarrer", "en": "Yes, start"},
    "confirm.no": {"fr": "Non, retour", "en": "No, go back"},
    "session.collecting": {
        "fr": "Collecte des IP actives...",
        "en": "Collecting active IPs...",
    },
    "session.checking_tunnels": {
        "fr": "Recherche de tunnels potentiels parmi les IP collectées...",
        "en": "Checking for potential tunnels in collected IPs...",
    },
    "session.no_tunnels": {
        "fr": "Aucun tunnel potentiel identifié",
        "en": "No potential tunnels identified",
    },
    "session.tunnel_warning": {
        "fr": "ATTENTION ! Guardian a détecté {count} IP dans votre session qui pourraient "
        "servir de tunnel de connexion et compromettre la sécurité de la session si elles "
        "sont ajoutées à la liste blanche.\nSauf si vous savez ce que vous faites, il est "
        "FORTEMENT RECOMMANDÉ de NE PAS les ajouter.\nExclure une IP de cette liste "
        "déconnectera probablement les joueurs qui passent par elle.\nSi cela arrive, "
        "vérifiez le pare-feu Windows de votre ami et le vôtre pour comprendre pourquoi "
        "il ne peut pas se connecter directement.\nS'il s'agit d'un faux positif, ajoutez "
        "ces IP manuellement à votre liste blanche pour ne plus voir ce message.\n\n"
        "Sélectionnez les IP potentiellement dangereuses à garder malgré tout, s'il y en a.",
        "en": "WARNING! Guardian has detected {count} IP(s) in your current session that "
        "may be used for connection tunnelling, and may break session security if added "
        "to the whitelist.\nUnless you know what you're doing, it is HIGHLY RECOMMENDED "
        "that you DO NOT allow these IPs to be added to the whitelist.\nPlease note that "
        "excluding an IP from this list will likely result in players connected through "
        "that IP to be dropped from the session.\nIf this happens, then you may have to "
        "check both you and your friend's Windows Firewall settings to see why they can't "
        "directly connect to you.\nIf this is a false-positive and you are sure an IP is a "
        "direct connection, you can prevent this message from appearing by manually adding "
        "them to your Whitelist.\n\nSelect the potentially session-security-breaking IPs "
        "you wish to keep whitelisted, if any.",
    },
    "session.select_kick": {
        "fr": "Sélectionnez les IP à expulser",
        "en": "Select IPs to kick",
    },
    "session.kicking": {
        "fr": "Expulsion des inconnus...",
        "en": "Kicking unknowns...",
    },
    "session.collecting_bar": {
        "fr": "Collecte des IP de la session",
        "en": "Collecting session IPs",
    },
    # -- explications des modes ------------------------------------------------
    "explain.solo": {
        "fr": "Personne ne peut se connecter à votre session, mais l'activité essentielle de "
        "R* et du SocialClub passe toujours.\nSi vous êtes en session avec d'autres joueurs, "
        "ils perdront la connexion avec vous.",
        "en": "No one can connect to your game session, but critical R* and SocialClub "
        "activity will still go through.\nIf you are in a session with any other players, "
        "they will lose connection to you.",
    },
    "explain.whitelist": {
        "fr": "Seules les IP de votre liste blanche peuvent se connecter à vous.\nSi vous "
        "êtes l'hôte, toute personne absente de la liste perdra probablement la connexion."
        "\nSi vous n'êtes pas l'hôte (et qu'un joueur n'est pas dans votre liste), c'est "
        "vous qui perdrez la connexion avec les autres.",
        "en": "Only IP addresses in your Whitelist will be allowed to connect to you.\nIf you "
        "are the host of a session, anyone not in your Whitelist will likely lose connection "
        "to the session.\nIf you are not the host (and any player in the session is not in "
        "your Whitelist), you will lose connection to everyone else.",
    },
    "explain.blacklist": {
        "fr": "Les IP de votre liste noire ne peuvent pas se connecter à vous.\nUne connexion "
        "relayée par les serveurs R* est aussi bloquée par sécurité.\nCe mode est DÉCONSEILLÉ "
        "car GTA Online reroute le trafic si seules quelques IP sont bloquées.",
        "en": "IP addresses in your Blacklist will not be allowed to connect to you.\nIf a "
        "connection is routed through R* servers, that connection will also be blocked as a "
        "security measure.\nThis mode is NOT RECOMMENDED as GTA Online has custom routing if "
        "only a handful of IP addresses are blocked.",
    },
    "explain.locked": {
        "fr": "Ce mode bloque toutes les demandes de connexion : aucun nouveau joueur ne peut "
        "entrer.\nLes joueurs déjà présents ne sont pas expulsés. Ce mode empêche aussi "
        "d'entrer via les serveurs R* si quelqu'un passe par un tunnel R*.\nEn revanche, un "
        "joueur qui quitte la session ne pourra pas revenir.",
        "en": "This mode blocks all join requests, preventing new players from entering the "
        "session.\nAnyone already in the session will not be kicked out. This mode prevents "
        "people from entering the session through R* servers if someone is being tunnelled "
        "through a R* IP.\nHowever, if a player leaves the session, they will not be able to "
        "join again.",
    },
    "explain.auto_whitelist": {
        "fr": "Comme la session liste blanche, mais tous les joueurs actuellement présents "
        "sont ajoutés temporairement à la liste blanche.\nCes IP collectées sont oubliées à "
        "la fin de la session.\nSi Guardian détecte qu'un joueur passe par les serveurs R*, "
        "vous serez averti et pourrez choisir de l'ajouter quand même.\nDans ce cas, votre "
        "session risque de ne pas être correctement protégée.",
        "en": "Similar to Whitelisted session, except everybody currently in the session is "
        "temporarily added to your whitelist, which prevents them from being kicked.\nAny "
        "automatically collected IPs will be lost once the session ends.\nIf Guardian detects "
        "that a player in your session is being routed through R* servers, you will be warned "
        "and prompted whether you wish to add this IP to the temporary whitelist.\nIf you do "
        "decide to allow these IPs, your session may not properly protected.",
    },
    "explain.kick_unknowns": {
        "fr": "Tente d'expulser de la session toute IP absente de votre liste blanche.\nCette "
        "méthode est DÉCONSEILLÉE : le jeu peut faire passer le trafic d'inconnus par des IP "
        "de votre liste blanche.",
        "en": "Attempts to kick any IP that is not on your Whitelist out of the session.\n"
        "Keeping your sessions safe in this manner is NOT RECOMMENDED, as clients may try to "
        "route unknown player traffic through IPs that are on your Whitelist.",
    },
    "explain.new_session": {
        "fr": "Vous sépare de la session actuelle pour vous retrouver seul. Être le seul "
        "joueur garantit que vous êtes l'hôte de la session.",
        "en": "Splits you from the current session so you are alone. Being the only player "
        "in a session ensures that you are the session Host.",
    },
    "explain.kick_by_ip": {
        "fr": "Capture les IP de votre session, puis vous laisse choisir lesquelles expulser."
        "\nDÉCONSEILLÉ pour la même raison que l'expulsion des inconnus.",
        "en": "Captures IPs in your session, then allows you to choose which IPs to kick.\n"
        "This mode is NOT RECOMMENDED for the same reason that kicking unknowns may not work.",
    },
    # -- listes ------------------------------------------------------------
    "lists.which": {
        "fr": "Quelle liste voulez-vous modifier ?",
        "en": "Which list do you want to edit?",
    },
    "lists.whitelist": {"fr": "Liste blanche", "en": "Whitelist"},
    "lists.blacklist": {"fr": "Liste noire", "en": "Blacklist"},
    "lists.back": {"fr": "Retour", "en": "Go back"},
    "lists.action": {
        "fr": "Que voulez-vous faire avec la {name} ?",
        "en": "What do you want to do with the {name}?",
    },
    "lists.list": {"fr": "Afficher", "en": "List"},
    "lists.add": {"fr": "Ajouter", "en": "Add"},
    "lists.edit": {"fr": "Modifier", "en": "Edit"},
    "lists.delete": {"fr": "Supprimer", "en": "Delete"},
    "lists.name": {"fr": "Nom", "en": "Name"},
    "lists.ip": {"fr": "Adresse IP", "en": "IP address"},
    "lists.entry": {
        "fr": "IP : {ip}\tNom : {name}",
        "en": "IP Address: {ip}\tName: {name}",
    },
    "lists.empty": {"fr": "La {name} est vide", "en": "No {name} entries"},
    "lists.which_edit": {
        "fr": "Quelle entrée voulez-vous modifier ?",
        "en": "Which entry do you want to edit?",
    },
    "lists.which_delete": {
        "fr": "Quelle entrée voulez-vous supprimer ?",
        "en": "Which entry do you want to delete?",
    },
    "lists.not_found": {
        "fr": "Aucune IP trouvée pour le nom {name}",
        "en": "No ip found with name {name}",
    },
    # -- validation ----------------------------------------------------------
    "valid.invalid_ip": {"fr": "IP invalide", "en": "Invalid IP"},
    "valid.ip_exists": {"fr": "IP déjà dans la liste", "en": "IP already in list"},
    "valid.name_exists": {"fr": "Nom déjà dans la liste", "en": "Name already in list"},
    "print.invalid_ip": {"fr": "IP invalide : {ip}", "en": "Invalid IP: {ip}"},
    # -- démarrage -------------------------------------------------------------
    "main.need_admin": {
        "fr": "Veuillez relancer en tant qu'administrateur",
        "en": "Please restart as administrator",
    },
    "main.press_enter": {
        "fr": "Appuyez sur Entrée pour quitter.",
        "en": "Press enter to exit.",
    },
    "main.init": {"fr": "Initialisation...", "en": "Initialising..."},
    "main.integrity": {
        "fr": "Démarrage refusé : échec de la vérification d'intégrité de WinDivert ({e})",
        "en": "Refusing to start: WinDivert integrity check failed ({e})",
    },
    "main.filter_failed": {
        "fr": "Impossible d'ouvrir le filtre WinDivert, arrêt propre : {e}",
        "en": "Could not open the WinDivert filter, exiting cleanly: {e}",
    },
    "main.self_test": {
        "fr": "Auto-test : initialisé, arrêt normal",
        "en": "Self-test: initialised, exiting normally",
    },
    # -- anomalies -------------------------------------------------------------
    "anomaly.burst": {
        "fr": "rafale de {pps:.0f} paquets/s, normale {base:.0f}",
        "en": "burst of {pps:.0f} packets/s, normal {base:.0f}",
    },
    "anomaly.targeted": {"fr": " (ciblée)", "en": " (targeted)"},
    "anomaly.huge": {
        "fr": "paquets énormes ({size} o, max des autres {others} o)",
        "en": "huge packets ({size} B, others' max {others} B)",
    },
    "anomaly.tiny": {
        "fr": "{count} petits paquets identiques de {size} o",
        "en": "{count} tiny identical packets of {size} B",
    },
    "reason.burst": {"fr": "rafale", "en": "burst"},
    "reason.huge": {"fr": "paquets énormes", "en": "huge packets"},
    "reason.tiny": {"fr": "petits paquets répétés", "en": "repeated tiny packets"},
    "level.normal": {"fr": "normal", "en": "normal"},
    "level.inhabituel": {"fr": "inhabituel", "en": "unusual"},
    "level.suspect": {"fr": "suspect", "en": "suspect"},
    "level.learning": {"fr": "apprent.", "en": "learning"},
    # -- vue en direct ---------------------------------------------------------
    "live.windows_only": {
        "fr": "La vue Session en direct nécessite Windows.",
        "en": "The Live session view requires Windows.",
    },
    "live.title": {
        "fr": "Guardian — Session en direct (version de test)",
        "en": "Guardian — Live session (test build)",
    },
    "live.status": {
        "fr": "Bouclier auto (rouge, {minutes} min) : {auto}   Enregistrement : {rec}",
        "en": "Auto shield (red, {minutes} min): {auto}   Recording: {rec}",
    },
    "live.on": {"fr": "ACTIVÉ", "en": "ON"},
    "live.off": {"fr": "désactivé", "en": "off"},
    "live.rec_on": {"fr": "ACTIVÉ ({path})", "en": "ON ({path})"},
    "live.header": {
        "fr": "{n:>2}  {ip:<15}  {country:<5}  {seen:<10}  {pps:>6}  {bps:>8}  {avg:>5}  "
        "{max:>5}  {state:<10}  Pseudo",
        "en": "{n:>2}  {ip:<15}  {country:<5}  {seen:<10}  {pps:>6}  {bps:>8}  {avg:>5}  "
        "{max:>5}  {state:<10}  Nickname",
    },
    "live.col.country": {"fr": "Pays", "en": "Ctry"},
    "live.col.seen": {"fr": "Vu depuis", "en": "First seen"},
    "live.col.pps": {"fr": "Paq/s", "en": "Pkt/s"},
    "live.col.bps": {"fr": "Oct/s", "en": "B/s"},
    "live.col.avg": {"fr": "Moy", "en": "Avg"},
    "live.col.max": {"fr": "Max", "en": "Max"},
    "live.col.state": {"fr": "État", "en": "State"},
    "live.no_peers": {"fr": "(aucun pair connecté)", "en": "(no connected peer)"},
    "live.keys": {
        "fr": "[B] Bloquer  [P] Pseudo  [D] Débloquer  [A] Bouclier auto  "
        "[E] Enregistrement  [Q] Retour",
        "en": "[B] Block  [P] Nickname  [D] Unblock  [A] Auto shield  "
        "[E] Recording  [Q] Back",
    },
    "live.blocked": {"fr": "BLOQUÉE", "en": "BLOCKED"},
    "live.blocked_min": {"fr": "BLOQUÉE {m} min", "en": "BLOCKED {m} min"},
    "live.ask_block": {
        "fr": "Numéro de la ligne à bloquer : ",
        "en": "Row number to block: ",
    },
    "live.ask_pseudo": {
        "fr": "Pseudo / note (optionnel) : ",
        "en": "Nickname / note (optional): ",
    },
    "live.ask_row": {"fr": "Numéro de la ligne : ", "en": "Row number: "},
    "live.ask_pseudo_for": {"fr": "Pseudo pour {ip} : ", "en": "Nickname for {ip}: "},
    "live.ask_unblock": {
        "fr": "Numéro de l'IP à débloquer : ",
        "en": "Number of the IP to unblock: ",
    },
    "live.ev.blocked": {
        "fr": "IP {ip} bloquée et ajoutée à la liste noire",
        "en": "IP {ip} blocked and added to the blacklist",
    },
    "live.ev.auto": {
        "fr": "Bouclier auto : {ip} bloqué ({reason}) pour {minutes} min",
        "en": "Auto shield: {ip} blocked ({reason}) for {minutes} min",
    },
    "live.ev.unblocked": {"fr": "IP {ip} débloquée", "en": "IP {ip} unblocked"},
    "live.ev.expired": {
        "fr": "Blocage automatique de {ip} expiré",
        "en": "Automatic block of {ip} expired",
    },
    "live.label": {
        "fr": "{pseudo} [bloqué le {date}]",
        "en": "{pseudo} [blocked on {date}]",
    },
    "live.label_nopseudo": {"fr": "Bloqué le {date}", "en": "Blocked on {date}"},
}


def get_language() -> str:
    global _current
    if _current is None:
        try:
            from config.configdata import ConfigData

            lang = str(ConfigData().data.get("language", DEFAULT_LANGUAGE))
        except Exception:
            lang = DEFAULT_LANGUAGE
        _current = lang if lang in LANGUAGES else DEFAULT_LANGUAGE
    return _current


def set_language(lang: str, persist: bool = True) -> None:
    """Change la langue ; ``persist`` l'enregistre dans data.json."""
    global _current
    if lang not in LANGUAGES:
        raise ValueError(f"langue inconnue : {lang}")
    _current = lang
    if persist:
        from config.configdata import ConfigData

        config = ConfigData()
        config.data["language"] = lang
        config.save()


def t(key: str, **kwargs: Any) -> str:
    """Texte traduit pour ``key`` (repli : anglais, puis la clé elle-même)."""
    entry = STRINGS.get(key)
    if entry is None:
        return key
    text = entry.get(get_language()) or entry.get("en") or key
    return text.format(**kwargs) if kwargs else text
