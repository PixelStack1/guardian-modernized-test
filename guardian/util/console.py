import sys
from ctypes import WinDLL, create_unicode_buffer

kernel32 = WinDLL("kernel32", use_last_error=True)


def get_console_title() -> str:
    BUF_SIZE = 256
    buffer = create_unicode_buffer(256)
    kernel32.GetConsoleTitleW(buffer, BUF_SIZE)
    return buffer.value


def set_console_title(title: str) -> None:
    kernel32.SetConsoleTitleW(title)


def get_original_console_title() -> str:
    return get_console_title().split(" - ")[0]


def attach_console() -> bool:
    """Exécutable fenêtré lancé avec ``--console`` : ouvre une console et y relie
    stdin/stdout/stderr. Sans effet si une console/sortie existe déjà."""
    if sys.stdout is not None and sys.stdin is not None:
        return False
    if not kernel32.AllocConsole():
        return False
    sys.stdout = open("CONOUT$", "w", encoding="utf-8")  # noqa: SIM115
    sys.stderr = sys.stdout
    sys.stdin = open("CONIN$", encoding="utf-8")  # noqa: SIM115
    return True
