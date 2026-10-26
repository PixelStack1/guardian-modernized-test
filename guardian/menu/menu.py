from __future__ import annotations

import contextlib
import logging
import time
import webbrowser
from enum import Enum
from multiprocessing import Pipe
from typing import Any, cast

import questionary
from tqdm import trange

from config.configdata import ConfigData
from config.globallist import Blacklist, Whitelist
from dispatcher.context import Context
from menu.hostfirst import (
    FilterStartFailed,
    drain,
    host_first_countdown,
    wait_until_started,
)
from menu.lists import Lists
from menu.livesession import run_live_session
from network.sessions import (
    AbstractPacketFilter,
    BlacklistSession,
    HostFirstSession,
    IPCollector,
    LockedSession,
    SoloSession,
    WhitelistSession,
)
from util.constants import DISCORD_URL, UI_STYLE
from util.dynamicblacklist import get_dynamic_blacklist
from util.i18n import LANGUAGES, set_language, t
from util.network import get_private_ip, get_public_ip, ip_in_cidr_block_set
from util.printer import pretty_print, print_invalid_ip
from validator.ip import IPValidator

debug_logger = logging.getLogger("debugger")

PRIVATE_IP = get_private_ip()
PUBLIC_IP = get_public_ip()


class Menu:
    parent_conn, child_conn = Pipe()
    context = Context(parent_conn)
    config = ConfigData()
    blacklist = Blacklist()
    whitelist = Whitelist()
    dynamic_blacklist = get_dynamic_blacklist()

    @staticmethod
    def main_menu() -> None:
        from menu.livesession import background_status_line, stop_background

        try:
            Menu._main_menu_loop(background_status_line)
        finally:
            stop_background()  # sortie du programme : jamais de processus orphelin

    @staticmethod
    def _main_menu_loop(status: Any) -> None:
        while True:
            try:
                line = status()
                if line:
                    pretty_print(line)
                answer = questionary.select(
                    t("menu.question"), Prompts.main_menu(), style=UI_STYLE
                ).ask()

                if callable(answer):
                    answer()
            except KeyboardInterrupt:
                return

    @staticmethod
    def confirm_session(
        session_type: type[AbstractPacketFilter] | str,
    ) -> Prompts.CONFIRM_SESSION_ANSWER:
        name_key, explanation_key = Prompts.EXPLANATIONS[session_type]
        pretty_print(t(explanation_key))
        return cast(
            Prompts.CONFIRM_SESSION_ANSWER,
            questionary.select(
                t("confirm.question", name=t(name_key)),
                Prompts.confirm_options(),
                style=UI_STYLE,
            ).ask(),
        )

    @staticmethod
    def launch_session(
        session_type: type[AbstractPacketFilter], *args: Any, **kwargs: Any
    ) -> None:
        answer = Menu.confirm_session(session_type)
        if answer and answer == Prompts.CONFIRM_SESSION_ANSWER.YES:
            session = session_type(*args, **kwargs)
            Menu.context.add_filter(session)
            Menu.context.start_latest_filter()

    @staticmethod
    def launch_solo_session() -> None:
        Menu.launch_session(
            SoloSession, priority=Menu.context.priority, connection=Menu.child_conn
        )

    @staticmethod
    def launch_whitelisted_session() -> None:
        ip_set = set()
        debug_logger.debug("Validating whitelisted IPs")
        for ip, _name in Menu.whitelist:
            try:
                ip_calc = IPValidator.validate_get(ip)
                ip_set.add(ip_calc)
            except questionary.ValidationError:
                print_invalid_ip(ip)
        Menu.launch_session(
            WhitelistSession,
            ips=ip_set,
            priority=Menu.context.priority,
            connection=Menu.child_conn,
        )

    @staticmethod
    def launch_blacklisted_session() -> None:
        ip_set = set()
        debug_logger.debug("Validating blacklisted IPs")
        for ip, _name in Menu.blacklist:
            try:
                ip_calc = IPValidator.validate_get(ip)
                ip_set.add(ip_calc)
            except questionary.ValidationError:
                print_invalid_ip(ip)
        Menu.launch_session(
            BlacklistSession,
            ips=ip_set,
            priority=Menu.context.priority,
            connection=Menu.child_conn,
            blocks=Menu.dynamic_blacklist,
            known_allowed={ip for ip in (PRIVATE_IP, PUBLIC_IP) if ip},
        )

    @staticmethod
    def launch_locked_session() -> None:
        Menu.launch_session(
            LockedSession, priority=Menu.context.priority, connection=Menu.child_conn
        )

    @staticmethod
    def launch_host_first_session() -> None:
        answer = Menu.confirm_session(HostFirstSession)
        if not (answer and answer == Prompts.CONFIRM_SESSION_ANSWER.YES):
            return
        session = HostFirstSession(Menu.context.priority, connection=Menu.child_conn)
        drain(Menu.parent_conn)  # ignorer les anciens signaux des autres filtres
        Menu.context.add_filter(session)
        Menu.context.start_latest_filter()
        # Le compte à rebours ne démarre qu'une fois le filtre réellement lancé (max 10 s).
        # Filtre mort, sorti pendant l'attente ou WinDivert non ouvert : pas de
        # « Session ouverte » ni de compte à rebours, message d'erreur et retour au menu.
        try:
            wait_until_started(
                session, Menu.parent_conn, is_alive=session.process.is_alive
            )
        except FilterStartFailed as e:
            debug_logger.warning("Host-first filter failed to start: %s", e)
            print(t("host_first.failed"))
            Menu.context.kill_latest_filter()
            return
        # Ctrl+C n'interrompt que l'affichage : la réouverture reste automatique.
        with contextlib.suppress(KeyboardInterrupt):
            host_first_countdown(session)

    @staticmethod
    def launch_new_session() -> None:
        answer = Menu.confirm_session("New Session")
        if answer and answer == Prompts.CONFIRM_SESSION_ANSWER.YES:
            session = SoloSession(Menu.context.priority, connection=Menu.child_conn)
            Menu.context.add_filter(session)
            Menu.context.start_latest_filter()

    @staticmethod
    def launch_auto_whitelisted_session() -> None:
        answer = Menu.confirm_session("Auto-Whitelisted")
        if answer and answer == Prompts.CONFIRM_SESSION_ANSWER.YES:
            print(t("session.collecting"))
            ip_set = Menu.collect_active_ips()
            print(t("session.checking_tunnels"))
            potential_tunnels = {
                ip
                for ip in ip_set
                if ip_in_cidr_block_set(ip, Menu.dynamic_blacklist)
                and ip not in Menu.whitelist
            }
            if potential_tunnels:
                ip_answer = questionary.checkbox(
                    t("session.tunnel_warning", count=len(potential_tunnels)),
                    choices=list(potential_tunnels),
                    style=UI_STYLE,
                ).ask()
                for ip in ip_answer:
                    potential_tunnels.remove(ip)
                for ip in potential_tunnels:
                    ip_set.remove(ip)
            else:
                print(t("session.no_tunnels"))
            session = WhitelistSession(
                ip_set, Menu.context.priority, connection=Menu.child_conn
            )
            Menu.context.add_filter(session)
            Menu.context.start_latest_filter()

    @staticmethod
    def kick_unknowns() -> None:
        answer = Menu.confirm_session("Kick Unknowns")
        if answer and answer == Prompts.CONFIRM_SESSION_ANSWER.YES:
            ip_set = set()
            for ip, _name in Menu.whitelist:
                try:
                    ip_calc = IPValidator.validate_get(ip)
                    ip_set.add(ip_calc)
                except questionary.ValidationError:
                    print_invalid_ip(ip)
            session = WhitelistSession(
                ip_set, Menu.context.priority, connection=Menu.child_conn
            )
            Menu.context.add_filter(session)
            Menu.context.start_latest_filter()
            for _ in trange(10, ascii=True, desc=t("session.kicking")):
                time.sleep(1)
            Menu.context.kill_latest_filter()

    @staticmethod
    def kick_by_ip() -> None:
        answer = Menu.confirm_session("Kick by IP")
        if answer and answer == Prompts.CONFIRM_SESSION_ANSWER.YES:
            ip_set = Menu.collect_active_ips()
            choices = questionary.checkbox(
                t("session.select_kick"), list(ip_set), style=UI_STYLE
            ).ask()
            for ip in choices:
                ip_set.remove(ip)
            session = WhitelistSession(
                ip_set, Menu.context.priority, connection=Menu.child_conn
            )
            Menu.context.add_filter(session)
            Menu.context.start_latest_filter()
            for _ in trange(10, ascii=True, desc=t("session.kicking")):
                time.sleep(1)
            Menu.context.kill_latest_filter()

    @staticmethod
    def open_discord() -> None:
        print(t("menu.opening_discord"))
        webbrowser.open(DISCORD_URL)

    @staticmethod
    def choose_language() -> None:
        labels = {"fr": "Français", "en": "English"}
        answer = questionary.select(
            t("menu.choose_language"),
            [{"name": labels[lang], "value": lang} for lang in LANGUAGES],
            style=UI_STYLE,
        ).ask()
        if answer:
            set_language(answer)

    @staticmethod
    def quit() -> None:
        raise KeyboardInterrupt

    @staticmethod
    def collect_active_ips(duration_seconds: int = 60) -> set[str]:
        collector = IPCollector(Menu.context.priority, packet_count_min_threshold=15)
        collector.start()
        for _ in trange(duration_seconds, ascii=True, desc=t("session.collecting_bar")):
            time.sleep(1)
        collector.stop()
        return set(collector.ips)


class Prompts:
    @staticmethod
    def main_menu() -> list[dict[str, Any]]:
        """Construit à chaque affichage pour suivre la langue choisie."""
        return [
            {"name": t("menu.solo"), "value": Menu.launch_solo_session},
            {"name": t("menu.whitelist"), "value": Menu.launch_whitelisted_session},
            {"name": t("menu.blacklist"), "value": Menu.launch_blacklisted_session},
            {
                "name": t("menu.auto_whitelist"),
                "value": Menu.launch_auto_whitelisted_session,
            },
            {"name": t("menu.locked"), "value": Menu.launch_locked_session},
            {"name": t("menu.kick_unknowns"), "value": Menu.kick_unknowns},
            {"name": t("menu.new_session"), "value": Menu.launch_new_session},
            {"name": t("menu.host_first"), "value": Menu.launch_host_first_session},
            {"name": t("menu.kick_by_ip"), "value": Menu.kick_by_ip},
            {"name": t("menu.live"), "value": run_live_session},
            {"name": t("menu.edit_lists"), "value": Lists.choose_list},
            {"name": t("menu.language"), "value": Menu.choose_language},
            {"name": t("menu.discord"), "value": Menu.open_discord},
            {"name": t("menu.quit"), "value": Menu.quit},
        ]

    class CONFIRM_SESSION_ANSWER(Enum):
        YES = "y"
        NO = "n"

    @staticmethod
    def confirm_options() -> list[dict[str, Any]]:
        return [
            {"name": t("confirm.yes"), "value": Prompts.CONFIRM_SESSION_ANSWER.YES},
            {"name": t("confirm.no"), "value": Prompts.CONFIRM_SESSION_ANSWER.NO},
        ]

    # Mode -> (clé du nom affiché, clé de l'explication)
    EXPLANATIONS: dict[type[AbstractPacketFilter] | str, tuple[str, str]] = {
        SoloSession: ("menu.solo", "explain.solo"),
        HostFirstSession: ("menu.host_first", "explain.host_first"),
        WhitelistSession: ("menu.whitelist", "explain.whitelist"),
        BlacklistSession: ("menu.blacklist", "explain.blacklist"),
        LockedSession: ("menu.locked", "explain.locked"),
        "Auto-Whitelisted": ("menu.auto_whitelist", "explain.auto_whitelist"),
        "Kick Unknowns": ("menu.kick_unknowns", "explain.kick_unknowns"),
        "New Session": ("menu.new_session", "explain.new_session"),
        "Kick by IP": ("menu.kick_by_ip", "explain.kick_by_ip"),
    }
