"""Vue en direct : frame à la taille de la fenêtre, pagination, écran alternatif, touches."""

import io

from guardian.menu import livesession as ls
from guardian.network.anomaly import SessionMonitor
from tests.test_totalblock import FakeList


def make_ctrl(**kw):
    kw.setdefault("auto_block", False)
    kw.setdefault("auto_block_available", True)
    return ls.LiveSessionController({}, FakeList(), clock=lambda: 1000.0, **kw)


def test_paginate_bounds():
    assert ls.paginate(32, 20, 0) == (0, 20, 0, 2)
    assert ls.paginate(32, 20, 1) == (20, 32, 1, 2)
    assert ls.paginate(32, 20, 9) == (20, 32, 1, 2)
    assert ls.paginate(32, 20, -3) == (0, 20, 0, 2)
    assert ls.paginate(0, 20, 0) == (0, 0, 0, 1)
    assert ls.paginate(5, 0, 0)[3] == 5


def test_fit_line_ignores_ansi_and_never_wraps():
    line = "\x1b[31m" + "x" * 50 + "\x1b[0m"
    out = ls.fit_line(line, 20)
    assert out.startswith("\x1b[31m") and out.count("x") == 19
    assert ls.fit_line("abc", 80) == "abc"


def test_fit_frame_header_top_keys_bottom_pagination():
    head = ["TITLE", "status"]
    rows = [f"row{i}" for i in range(32)]
    tail = ["", "event", "", "KEYS"]
    frame = ls.fit_frame(head, rows, tail, 12, 0, 32)
    assert len(frame) <= 12
    assert frame[0] == "TITLE" and frame[-1] == "KEYS"
    per = 12 - len(head) - 2
    assert frame[2 : 2 + per] == rows[:per]
    assert f"1–{per}" in frame[2 + per] and "32" in frame[2 + per]
    last = ls.fit_frame(head, rows, tail, 12, 99, 32)
    assert last[0] == "TITLE" and last[-1] == "KEYS" and "row31" in last
    assert len(last) <= 12


def test_render_fits_window_and_translates():
    ctrl = make_ctrl()
    out = ls.render(SessionMonitor(), ctrl, [], "off", 0.0, size=(40, 15))
    lines = out.split("\n")
    assert len(lines) <= 15
    import re

    vis = [re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", x) for x in lines]
    assert all(len(v) <= 39 for v in vis)
    assert "Session" in vis[0]


def test_rows_per_page_matches_frame():
    ctrl = make_ctrl()
    head = ls.render_head(ctrl, "")
    n = ls.rows_per_page(30, len(head))
    rows = [str(i) for i in range(100)]
    frame = ls.fit_frame(head, rows, ["KEYS"], 30, 0, 100)
    assert sum(1 for x in frame if x.isdigit()) == n


def test_live_screen_alt_buffer_and_in_place():
    buf = io.StringIO()
    s = ls.LiveScreen(buf)
    s.enter()
    s.draw("a\nb")
    s.leave()
    s.leave()
    out = buf.getvalue()
    assert out.startswith("\x1b[?1049h")
    assert "\x1b[Ha\x1b[K\nb\x1b[K\x1b[J" in out
    assert out.count("\x1b[?1049l") == 1


def test_read_key_special_and_page_step():
    seq = iter(["\xe0", "Q"])
    assert ls.read_key(lambda: next(seq), lambda: True) == "pgdn"
    seq = iter(["\x00", "I"])
    assert ls.read_key(lambda: next(seq), lambda: True) == "pgup"
    assert ls.read_key(lambda: "A", lambda: False) == "a"
    assert (
        ls.page_step("pgdn") == 1 and ls.page_step("-") == -1 and ls.page_step("a") == 0
    )


class FakeConfig:
    def __init__(self):
        self.data, self.saved = {}, 0

    def save(self):
        self.saved += 1


class FakeRecorder:
    active = False

    def start(self):
        self.active = True

    def stop(self):
        self.active = False


def no_prompt(_text):
    raise AssertionError("A/T ne doivent afficher aucune invite")


def test_toggle_auto_shield_no_prompt_persists_and_header_updates():
    ctrl, cfg = make_ctrl(), FakeConfig()
    ls.handle_key("a", ctrl, [], {}, FakeRecorder(), no_prompt, cfg)
    assert ctrl.auto_block is True
    assert cfg.data[ls.AUTO_BLOCK_KEY] is True and cfg.saved == 1
    head = " ".join(ls.render_head(ctrl, "off"))
    assert "ACTIVÉ" in head or "ON" in head
    frame = ls.render(SessionMonitor(), ctrl, [], "off", 0.0, size=(200, 30))
    assert ctrl.toggle_msg is not None and ctrl.toggle_msg[0] in frame
    ls.handle_key("a", ctrl, [], {}, FakeRecorder(), no_prompt, cfg)
    assert ctrl.auto_block is False and cfg.data[ls.AUTO_BLOCK_KEY] is False


def test_toggle_total_and_recording_without_prompt():
    ctrl, cfg, rec = make_ctrl(), FakeConfig(), FakeRecorder()
    ls.handle_key("t", ctrl, [], {}, rec, no_prompt, cfg)
    assert ctrl.total_block is True and cfg.data[ls.TOTAL_BLOCK_KEY] is True
    ls.handle_key("e", ctrl, [], {}, rec, no_prompt, cfg)
    assert rec.active


def test_prompt_keys_use_prompt_and_ignore_bad_input():
    ctrl = make_ctrl()
    asked = []

    def prompt(text):
        asked.append(text)
        return "nope"

    for k in ("b", "p", "d"):
        ls.handle_key(k, ctrl, [], {"203.0.113.5": 9e9}, FakeRecorder(), prompt)
    assert len(asked) == 3 and "203.0.113.5" in asked[2]


def test_status_words_colored_green_red_fr_en():
    from colorama import Fore, Style

    from util import i18n

    try:
        for lang, on, off in (("fr", "ACTIVÉ", "désactivé"), ("en", "ON", "off")):
            i18n.set_language(lang, persist=False)
            assert ls.status_word(True) == Fore.GREEN + on + Style.RESET_ALL
            assert ls.status_word(False) == Fore.RED + off + Style.RESET_ALL
            rec = ls.recording_status(True, "x.log")
            assert rec == Fore.GREEN + on + Style.RESET_ALL + " (x.log)"
            assert ls.recording_status(False) == ls.status_word(False)
            ctrl = make_ctrl(auto_block=True)
            head = ls.render_head(ctrl, ls.recording_status(False))
            status = next(h for h in head if ls.status_word(True) in h)
            assert ls.status_word(False) in status  # enregistrement désactivé, rouge
            total = i18n.t(
                "live.total_status",
                minutes=ls.TOTAL_BLOCK_SECONDS // 60,
                state=ls.status_word(False),
            )
            assert total in head and Fore.GREEN not in total
            # Les codes couleur n'entrent pas dans le calcul de largeur.
            plain = ls._ANSI.sub("", status)
            fitted = ls.fit_line(status, 30)
            assert len(ls._ANSI.sub("", fitted)) == min(29, len(plain))
    finally:
        i18n.set_language("fr", persist=False)


def test_no_test_version_marker():
    from util import i18n

    for key in ("live.title", "menu.live"):
        for text in i18n.STRINGS[key].values():
            assert "test" not in text.lower()


def test_toggle_messages_single_line_replaced_and_expire():
    from colorama import Fore

    now = [1000.0]
    ctrl = ls.LiveSessionController(
        {}, FakeList(), clock=lambda: now[0], auto_block_available=True
    )
    cfg = FakeConfig()
    for key in ("a", "t", "a", "t", "a"):
        ls.handle_key(key, ctrl, [], {}, FakeRecorder(), no_prompt, cfg)
    frame = ls.render(SessionMonitor(), ctrl, [], "off", 0.0, size=(200, 30))
    shown = [
        line
        for line in frame.split("\n")
        if ls._ANSI.sub("", line).startswith(
            ("Bouclier auto :", "Blocage total :", "Auto shield:", "Total block:")
        )
    ]
    assert len(shown) == 1  # un seul message, le dernier (A -> bouclier activé)
    assert Fore.GREEN in shown[0]
    ls.handle_key("a", ctrl, [], {}, FakeRecorder(), no_prompt, cfg)
    assert ctrl.auto_block is False
    assert ctrl.toggle_msg is not None and Fore.RED in ctrl.toggle_msg[0]
    now[0] += ls.TOGGLE_MSG_SECONDS + 1
    assert ls.toggle_line(ctrl) == []
    assert ctrl.toggle_msg is None
