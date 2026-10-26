import os

import PyInstaller.__main__

version = "3.6.0.dev0"


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
            "--specpath",
            "spec",
        )
    )
