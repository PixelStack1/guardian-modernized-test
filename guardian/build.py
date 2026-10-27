import os

import PyInstaller.__main__

version = "3.6.1"

# Seuls QtCore/QtGui/QtWidgets (PySide6-Essentials) sont utilisés : tout le reste
# est exclu pour réduire la taille de l'exe onefile (donc sa décompression à
# chaque lancement).
QT_USED = ("QtCore", "QtGui", "QtWidgets")
QT_EXCLUDED = (
    "Qt3DAnimation",
    "Qt3DCore",
    "Qt3DExtras",
    "Qt3DInput",
    "Qt3DLogic",
    "Qt3DRender",
    "QtBluetooth",
    "QtCharts",
    "QtConcurrent",
    "QtDBus",
    "QtDataVisualization",
    "QtDesigner",
    "QtGraphs",
    "QtHelp",
    "QtHttpServer",
    "QtLocation",
    "QtMultimedia",
    "QtMultimediaWidgets",
    "QtNetwork",
    "QtNetworkAuth",
    "QtNfc",
    "QtOpenGL",
    "QtOpenGLWidgets",
    "QtPdf",
    "QtPdfWidgets",
    "QtPositioning",
    "QtPrintSupport",
    "QtQml",
    "QtQuick",
    "QtQuick3D",
    "QtQuickControls2",
    "QtQuickWidgets",
    "QtRemoteObjects",
    "QtScxml",
    "QtSensors",
    "QtSerialBus",
    "QtSerialPort",
    "QtSpatialAudio",
    "QtSql",
    "QtStateMachine",
    "QtSvg",
    "QtSvgWidgets",
    "QtTest",
    "QtTextToSpeech",
    "QtUiTools",
    "QtWebChannel",
    "QtWebEngineCore",
    "QtWebEngineQuick",
    "QtWebEngineWidgets",
    "QtWebSockets",
    "QtWebView",
    "QtXml",
)
NOTICE = "THIRD_PARTY_NOTICES.txt"


def _here(*parts: str) -> str:
    return os.path.abspath(os.path.join("guardian", *parts))


def pyinstaller_args() -> list[str]:
    return [
        os.path.join("guardian", "__main__.py"),
        # Un seul .exe (onefile) conservé ; pas d'UPX (décompression plus lente
        # et faux positifs antivirus).
        "--onefile",
        "--noupx",
        "--icon",
        "logo.ico",
        "--uac-admin",
        # Lot 5 : interface PySide6 fenêtrée (pas de console ; --console en ouvre une).
        "--windowed",
        # Écran affiché par le chargeur pendant la décompression (avant Python).
        "--splash",
        _here("assets", "splash.png"),
        "--collect-submodules",
        "gui",
        *(arg for mod in QT_USED for arg in ("--hidden-import", f"PySide6.{mod}")),
        # Modules Qt inutiles exclus (taille de l'exe et temps de décompression).
        *(arg for mod in QT_EXCLUDED for arg in ("--exclude-module", f"PySide6.{mod}")),
        "--name",
        f"Guardian-{version}",
        "--version-file",
        "version.txt",
        # Base de géolocalisation hors ligne (util/geoip.py la lit sous util/).
        "--add-data",
        _here("util", "geoip_ipv4.bin.gz") + os.pathsep + "util",
        # Plages VPN/hébergeurs hors ligne (util/vpn.py, lot 3).
        "--add-data",
        _here("util", "vpn_ipv4.bin.gz") + os.pathsep + "util",
        # Avis LGPL (PySide6) livré dans l'exe ; lu par « À propos · licences ».
        "--add-data",
        _here(NOTICE) + os.pathsep + ".",
        "--specpath",
        "spec",
    ]


def build() -> None:
    PyInstaller.__main__.run(pyinstaller_args())
