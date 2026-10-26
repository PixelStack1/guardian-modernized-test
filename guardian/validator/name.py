from collections.abc import Callable

from prompt_toolkit.document import Document
from questionary import ValidationError, Validator

from config.globallist import Blacklist, GlobalList, Whitelist
from util.i18n import t


class NameValidator(Validator):
    def __init__(self, global_list: Callable[[], GlobalList]):
        self.list = global_list()

    def validate(self, document: Document) -> None:
        name = document.text
        if self.list.has(name):
            raise ValidationError(
                message=t("valid.name_exists"), cursor_position=len(name)
            )


class NameInBlacklist(NameValidator):
    def __init__(self) -> None:
        super().__init__(Blacklist)


class NameInWhitelist(NameValidator):
    def __init__(self) -> None:
        super().__init__(Whitelist)
