"""Raccourcis clavier GLOBAUX (lot 7), via l'API Windows RegisterHotKey.

Les touches sont enregistrées dans un fil dédié qui tourne une boucle de messages
(obligatoire : WM_HOTKEY arrive dans le fil qui a enregistré la touche). Aucun
hook clavier, aucune lecture des frappes : Windows ne nous signale QUE nos
combinaisons. Rien ne touche le jeu. Le rappel est appelé depuis ce fil :
l'appelant (la GUI) le renvoie dans son fil principal.
"""

from __future__ import annotations

import logging
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

logger = logging.getLogger(__name__)

MOD_ALT = 0x0001
MOD_CONTROL = 0x0002
MOD_SHIFT = 0x0004
MOD_NOREPEAT = 0x4000
WM_HOTKEY = 0x0312
WM_QUIT = 0x0012
VK_F12 = 0x7B


@dataclass(frozen=True)
class Hotkey:
    action: str  # nom de l'action (emergency, panic, auto, total, lock)
    mods: int
    vk: int
    text: str  # affichage, ex. « Ctrl+Alt+F12 »

    @property
    def label_key(self) -> str:
        return f"hotkey.{self.action}"


def _letter(c: str) -> int:
    return ord(c.upper())


# Ctrl+Alt : combinaisons peu utilisées par les jeux ; F12 isolé pour l'urgence.
DEFAULT_HOTKEYS: tuple[Hotkey, ...] = (
    Hotkey("emergency", MOD_CONTROL | MOD_ALT, VK_F12, "Ctrl+Alt+F12"),
    Hotkey("panic", MOD_CONTROL | MOD_ALT, _letter("X"), "Ctrl+Alt+X"),
    Hotkey("auto", MOD_CONTROL | MOD_ALT, _letter("A"), "Ctrl+Alt+A"),
    Hotkey("total", MOD_CONTROL | MOD_ALT, _letter("T"), "Ctrl+Alt+T"),
    Hotkey("lock", MOD_CONTROL | MOD_ALT, _letter("V"), "Ctrl+Alt+V"),
)


def hotkey_text(action: str, hotkeys: tuple[Hotkey, ...] = DEFAULT_HOTKEYS) -> str:
    for h in hotkeys:
        if h.action == action:
            return h.text
    return ""


class HotkeyApi(Protocol):
    def register(self, hid: int, mods: int, vk: int) -> bool: ...
    def unregister(self, hid: int) -> None: ...
    def next_hotkey(self) -> int | None:
        """Bloque jusqu'au prochain WM_HOTKEY (son id) ; None = fin de la boucle."""
        ...

    def wake(self, thread_id: int) -> None:
        """Fait sortir ``next_hotkey`` (WM_QUIT posté au fil)."""
        ...


class WindowsHotkeyApi:  # pragma: no cover - Windows uniquement
    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes
        self._user32 = ctypes.windll.user32
        self._msg = wintypes.MSG()

    def register(self, hid: int, mods: int, vk: int) -> bool:
        return bool(self._user32.RegisterHotKey(None, hid, mods | MOD_NOREPEAT, vk))

    def unregister(self, hid: int) -> None:
        self._user32.UnregisterHotKey(None, hid)

    def next_hotkey(self) -> int | None:
        msg = self._msg
        while True:
            r = self._user32.GetMessageW(self._ctypes.byref(msg), None, 0, 0)
            if r == 0 or r == -1:
                return None
            if msg.message == WM_HOTKEY:
                return int(msg.wParam)

    def wake(self, thread_id: int) -> None:
        self._user32.PostThreadMessageW(thread_id, WM_QUIT, 0, 0)


class GlobalHotkeys:
    """Fil des raccourcis globaux. ``start`` renvoie les actions refusées
    (combinaison déjà prise par un autre programme)."""

    def __init__(
        self,
        callback: Callable[[str], Any],
        hotkeys: tuple[Hotkey, ...] = DEFAULT_HOTKEYS,
        api_factory: Callable[[], HotkeyApi] | None = None,
    ) -> None:
        self.callback = callback
        self.hotkeys = hotkeys
        self._factory = api_factory
        self._thread: threading.Thread | None = None
        self._thread_id = 0
        self._api: HotkeyApi | None = None
        self._ready = threading.Event()
        self.registered: list[str] = []
        self.failed: list[str] = []
        self.error = ""

    @staticmethod
    def supported() -> bool:
        return sys.platform == "win32"

    def start(self, timeout: float = 2.0) -> list[str]:
        if self._thread is not None:
            return self.failed
        factory = self._factory
        if factory is None:
            if not self.supported():
                self.error = "Windows uniquement"
                return [h.action for h in self.hotkeys]
            factory = WindowsHotkeyApi
        self._thread = threading.Thread(
            target=self._run, args=(factory,), name="guardian-hotkeys", daemon=True
        )
        self._thread.start()
        self._ready.wait(timeout)
        return self.failed

    def _run(self, factory: Callable[[], HotkeyApi]) -> None:
        self._thread_id = threading.get_native_id()
        try:
            api = factory()
            self._api = api
            for i, h in enumerate(self.hotkeys, 1):
                try:
                    ok = api.register(i, h.mods, h.vk)
                except Exception:
                    ok = False
                (self.registered if ok else self.failed).append(h.action)
        except Exception as e:
            self.error = str(e)
            self.failed = [h.action for h in self.hotkeys]
            self._ready.set()
            return
        self._ready.set()
        try:
            while True:
                hid = api.next_hotkey()
                if hid is None:
                    break
                if 1 <= hid <= len(self.hotkeys):
                    try:
                        self.callback(self.hotkeys[hid - 1].action)
                    except Exception:
                        logger.exception("raccourci global : action impossible")
        except Exception:
            logger.exception("raccourcis globaux : boucle arrêtée")
        finally:
            for i, h in enumerate(self.hotkeys, 1):
                if h.action in self.registered:
                    try:
                        api.unregister(i)
                    except Exception:
                        logger.debug("unregister %s impossible", h.action)

    def stop(self, timeout: float = 2.0) -> None:
        """Libère les touches (dans le fil propriétaire) et arrête le fil."""
        th = self._thread
        if th is None:
            return
        if self._api is not None and th.is_alive():
            try:
                self._api.wake(self._thread_id)
            except Exception:
                logger.debug("réveil du fil des raccourcis impossible", exc_info=True)
        th.join(timeout)
        self._thread = None
