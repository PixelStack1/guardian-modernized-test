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
            "--name",
            f"Guardian-{version}",
            "--version-file",
            "version.txt",
            # Base de géolocalisation hors ligne (util/geoip.py la lit sous util/).
            "--add-data",
            os.path.abspath(os.path.join("guardian", "util", "geoip_ipv4.bin.gz"))
            + os.pathsep
            + "util",
            "--specpath",
            "spec",
        )
    )
