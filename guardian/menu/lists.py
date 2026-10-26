import questionary

from config.globallist import Blacklist, Whitelist
from util.constants import UI_STYLE
from util.i18n import t
from validator.ip import IPInBlacklist, IPInWhitelist
from validator.name import NameInBlacklist, NameInWhitelist


class Lists:
    ip_validators = {Whitelist: IPInWhitelist, Blacklist: IPInBlacklist}
    name_validators = {Whitelist: NameInWhitelist, Blacklist: NameInBlacklist}

    @staticmethod
    def list_name(global_list_type: type[Whitelist | Blacklist]) -> str:
        return t(
            "lists.whitelist" if global_list_type is Whitelist else "lists.blacklist"
        )

    @staticmethod
    def choose_list() -> None:
        while True:
            answer = questionary.select(
                t("lists.which"),
                [
                    {"name": t("lists.whitelist"), "value": Whitelist},
                    {"name": t("lists.blacklist"), "value": Blacklist},
                    {"name": t("lists.back"), "value": "return"},
                ],
                style=UI_STYLE,
            ).ask()
            if not answer or answer == "return":
                break
            Lists.edit_list(answer)

    @staticmethod
    def edit_list(global_list_type: type[Whitelist | Blacklist]) -> None:
        while True:
            answer = questionary.select(
                t("lists.action", name=Lists.list_name(global_list_type)),
                [
                    {"name": t("lists.list"), "value": Lists.list},
                    {"name": t("lists.add"), "value": Lists.add},
                    {"name": t("lists.edit"), "value": Lists.edit},
                    {"name": t("lists.delete"), "value": Lists.delete},
                    {"name": t("lists.back"), "value": "return"},
                ],
                style=UI_STYLE,
            ).ask()
            if not answer or answer == "return":
                break
            answer(global_list_type)

    @staticmethod
    def add(global_list_type: type[Whitelist | Blacklist]) -> None:
        global_list = global_list_type()
        name = questionary.text(
            t("lists.name"),
            style=UI_STYLE,
            validate=Lists.name_validators[global_list_type],
        ).ask()
        ip = questionary.text(
            t("lists.ip"),
            style=UI_STYLE,
            validate=Lists.ip_validators[global_list_type],
        ).ask()
        global_list.add(ip, name)
        global_list.save()

    @staticmethod
    def list(global_list_type: type[Whitelist | Blacklist]) -> None:
        global_list = global_list_type()
        if len(global_list):
            for ip, name in global_list:
                print(t("lists.entry", ip=ip, name=name))
        else:
            print(t("lists.empty", name=Lists.list_name(global_list_type)))

    @staticmethod
    def edit(global_list_type: type[Whitelist | Blacklist]) -> None:
        global_list = global_list_type()
        while True:
            name = questionary.select(
                t("lists.which_edit"),
                global_list.names,
                style=UI_STYLE,
            ).ask()
            ip = global_list.find(name)
            if not ip:
                print(t("lists.not_found", name=name))
                break
            new_name = questionary.text(
                t("lists.name"), style=UI_STYLE, default=name
            ).ask()
            new_ip = questionary.text(
                t("lists.ip"),
                style=UI_STYLE,
                default=ip,
                validate=Lists.ip_validators[global_list_type],
            ).ask()
            global_list.remove(ip)
            global_list.add(new_ip, new_name)
            global_list.save()
            break

    @staticmethod
    def delete(global_list_type: type[Whitelist | Blacklist]) -> None:
        global_list = global_list_type()
        name = questionary.select(
            t("lists.which_delete"),
            global_list.names,
            style=UI_STYLE,
        ).ask()
        ip = global_list.find(name)
        if ip:
            global_list.remove(ip)
            global_list.save()
