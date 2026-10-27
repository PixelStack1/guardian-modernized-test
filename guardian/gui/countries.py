"""Noms de pays en français et drapeaux emoji (calculés localement, aucun réseau)."""

NAMES_FR: dict[str, str] = {
    "FR": "France",
    "DE": "Allemagne",
    "ES": "Espagne",
    "IT": "Italie",
    "GB": "Royaume-Uni",
    "US": "États-Unis",
    "BR": "Brésil",
    "PL": "Pologne",
    "NL": "Pays-Bas",
    "BE": "Belgique",
    "CH": "Suisse",
    "CA": "Canada",
    "PT": "Portugal",
    "AT": "Autriche",
    "IE": "Irlande",
    "LU": "Luxembourg",
    "SE": "Suède",
    "NO": "Norvège",
    "DK": "Danemark",
    "FI": "Finlande",
    "CZ": "Tchéquie",
    "SK": "Slovaquie",
    "HU": "Hongrie",
    "RO": "Roumanie",
    "BG": "Bulgarie",
    "GR": "Grèce",
    "HR": "Croatie",
    "SI": "Slovénie",
    "RS": "Serbie",
    "UA": "Ukraine",
    "RU": "Russie",
    "BY": "Biélorussie",
    "TR": "Turquie",
    "MA": "Maroc",
    "DZ": "Algérie",
    "TN": "Tunisie",
    "EG": "Égypte",
    "ZA": "Afrique du Sud",
    "NG": "Nigeria",
    "SN": "Sénégal",
    "CI": "Côte d'Ivoire",
    "MX": "Mexique",
    "AR": "Argentine",
    "CL": "Chili",
    "CO": "Colombie",
    "PE": "Pérou",
    "VE": "Venezuela",
    "AU": "Australie",
    "NZ": "Nouvelle-Zélande",
    "JP": "Japon",
    "KR": "Corée du Sud",
    "CN": "Chine",
    "IN": "Inde",
    "SG": "Singapour",
    "HK": "Hong Kong",
    "TW": "Taïwan",
    "IL": "Israël",
    "SA": "Arabie saoudite",
    "AE": "Émirats arabes unis",
    "LT": "Lituanie",
    "LV": "Lettonie",
    "EE": "Estonie",
    "IS": "Islande",
    "MC": "Monaco",
    "AD": "Andorre",
    "MT": "Malte",
    "CY": "Chypre",
}


def flag(code: str) -> str:
    """Drapeau emoji (indicateurs régionaux) d'un code ISO à 2 lettres, sinon « 🏳 »."""
    code = (code or "").upper()
    if len(code) != 2 or not code.isascii() or not code.isalpha():
        return "🏳"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code)


def name(code: str) -> str:
    code = (code or "").upper()
    return NAMES_FR.get(code, code or "—")


def display(code: str) -> str:
    """« 🇫🇷 France » ; « — » si pays inconnu."""
    if not code or code == "—":
        return "— Inconnu"
    return f"{flag(code)} {name(code)}"


# Drapeaux simplifiés dessinés localement (Windows n'affiche pas les emoji drapeaux).
# (orientation « v »/« h », couleurs des bandes).
STRIPES: dict[str, tuple[str, tuple[str, ...]]] = {
    "FR": ("v", ("#0055a4", "#ffffff", "#ef4135")),
    "IT": ("v", ("#009246", "#ffffff", "#ce2b37")),
    "BE": ("v", ("#000000", "#fdda24", "#ef3340")),
    "IE": ("v", ("#169b62", "#ffffff", "#ff883e")),
    "RO": ("v", ("#002b7f", "#fcd116", "#ce1126")),
    "MX": ("v", ("#006847", "#ffffff", "#ce1126")),
    "NG": ("v", ("#008751", "#ffffff", "#008751")),
    "CI": ("v", ("#f77f00", "#ffffff", "#009e60")),
    "SN": ("v", ("#00853f", "#fdef42", "#e31b23")),
    "CA": ("v", ("#ff0000", "#ffffff", "#ff0000")),
    "DE": ("h", ("#000000", "#dd0000", "#ffce00")),
    "NL": ("h", ("#ae1c28", "#ffffff", "#21468b")),
    "LU": ("h", ("#ed2939", "#ffffff", "#00a1de")),
    "AT": ("h", ("#ed2939", "#ffffff", "#ed2939")),
    "PL": ("h", ("#ffffff", "#dc143c")),
    "UA": ("h", ("#0057b7", "#ffd700")),
    "RU": ("h", ("#ffffff", "#0039a6", "#d52b1e")),
    "HU": ("h", ("#cd2a3e", "#ffffff", "#436f4d")),
    "BG": ("h", ("#ffffff", "#00966e", "#d62612")),
    "LT": ("h", ("#fdb913", "#006a44", "#c1272d")),
    "EE": ("h", ("#0072ce", "#000000", "#ffffff")),
    "ES": ("h", ("#aa151b", "#f1bf00", "#f1bf00", "#aa151b")),
    "CO": ("h", ("#fcd116", "#fcd116", "#003893", "#ce1126")),
    "AR": ("h", ("#74acdf", "#ffffff", "#74acdf")),
    "CH": ("h", ("#da291c",)),
    "GB": ("h", ("#012169", "#c8102e", "#012169")),
    "US": ("h", ("#b22234", "#ffffff", "#b22234", "#ffffff", "#b22234")),
    "BR": ("h", ("#009c3b", "#ffdf00", "#009c3b")),
    "PT": ("v", ("#046a38", "#da291c", "#da291c")),
    "JP": ("h", ("#ffffff",)),
    "TR": ("h", ("#e30a17",)),
}
