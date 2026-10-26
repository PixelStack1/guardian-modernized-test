from textwrap import fill

from colorama import Fore

from util.i18n import t


def print_white(msg: str) -> None:
    print(Fore.LIGHTWHITE_EX + msg + Fore.RESET)


def print_invalid_ip(address: str) -> None:
    print_white(t("print.invalid_ip", ip=f'"{Fore.LIGHTCYAN_EX}{address}{Fore.RESET}"'))


def pretty_print(string: str) -> None:
    for paragraph in string.split("\n"):
        print(fill(paragraph), end="\n\n")
