import os

import PyInstaller.__main__

version = "3.6.1"


def build() -> None:
    PyInstaller.__main__.run(
        (
            os.path.join("guardian", "__main__.py"),
            "--onefile",
            "--noupx",
            "--icon",
            "logo.ico",
            "--uac-admin",
            # Lot 5 : interface PySide6 fenêtrée (pas de console ; --console en ouvre une).
            "--windowed",
            "--collect-submodules",
            "gui",
            "--hidden-import",
            "PySide6.QtCore",
            "--hidden-import",
            "PySide6.QtGui",
            "--hidden-import",
            "PySide6.QtWidgets",
            # Modules Qt inutiles exclus (taille de l'exe).
            *(
                arg
                for mod in (
                    "QtWebEngineCore",
                    "QtWebEngineWidgets",
                    "Qt3DCore",
                    "QtQml",
                    "QtQuick",
                    "QtMultimedia",
                    "QtNetwork",
                    "QtPdf",
                )
                for arg in ("--exclude-module", f"PySide6.{mod}")
            ),
            "--name",
            f"Guardian-{version}",
            "--version-file",
            "version.txt",
            # Base de géolocalisation hors ligne (util/geoip.py la lit sous util/).
            "--add-data",
            os.path.abspath(os.path.join("guardian", "util", "geoip_ipv4.bin.gz"))
            + os.pathsep
            + "util",
            # Plages VPN/hébergeurs hors ligne (util/vpn.py, lot 3).
            "--add-data",
            os.path.abspath(os.path.join("guardian", "util", "vpn_ipv4.bin.gz"))
            + os.pathsep
            + "util",
            "--specpath",
            "spec",
        )
    )
