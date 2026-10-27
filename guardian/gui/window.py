"""Fenêtre principale PySide6. Lecture par QTimer, jamais dans la capture.

Grille, marges et tailles reprises du CSS de la maquette (guardian-ui-mockup) :
barre latérale 220 px, contenu 14/16/10 px, écart 12 px, cartes rayon 12 px.
"""

from __future__ import annotations

import html
import time
from collections import deque
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtGui import QKeySequence, QResizeEvent, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QPushButton,
    QSizePolicy,
    QSlider,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gui import countries, style
from gui.core import GuiActions, Row, Settings, Snapshot, take_snapshot
from gui.widgets import (
    HEAD_H,
    ROW_H,
    AlertDelegate,
    FlowLayout,
    PlayersDelegate,
    Sparkline,
    Switch,
    SwitchRow,
    flag_icon,
    font,
    frame,
    label,
    repolish,
    set_pill,
    shield_pixmap,
)
from network.filters import TRUSTED_DEFAULT

__all__ = ["COLUMNS", "MainWindow", "flag_icon"]

REFRESH_MS = 500
HISTORY = 120  # 60 s à 500 ms
SPARK_BARS = 9
COLUMNS = ["PAYS", "ADRESSE IP", "PING", "PAQUETS/S", "STATUT", "ACTION"]
# Largeurs relatives mesurées sur la maquette (table de 599 px).
COL_RATIOS = [113, 147, 53, 118, 89, 79]
ACTION_COL = 5
BADGES_ROLE = Qt.ItemDataRole.UserRole + 1
MAX_ALERTS = 50
RED_WORDS = ("bloqu", "flood", "débit", "coupé", "erreur", "blocked", "error")
ORANGE_WORDS = ("récidiv", "vpn", "offender", "ping")


def alert_color(text: str) -> str:
    low = text.lower()
    if any(w in low for w in RED_WORDS):
        return style.RED
    if any(w in low for w in ORANGE_WORDS):
        return style.ORANGE
    return style.CYAN


def alert_html(text: str) -> str:
    """Partie avant « : » en gras (comme <strong> de la maquette)."""
    head, sep, rest = text.partition(" : ")
    if not sep:
        head, sep, rest = text.partition(": ")
    if sep and len(head) <= 40:
        return f"<b>{html.escape(head)} :</b> {html.escape(rest)}"
    return html.escape(text)


def new_events(prev: list[str], cur: list[str]) -> list[str]:
    """Événements apparus depuis le dernier instantané (liste glissante)."""
    for k in range(min(len(prev), len(cur)), 0, -1):
        if prev[-k:] == cur[:k]:
            return cur[k:]
    return cur


def panel(
    title: str, meta: str = ""
) -> tuple[QFrame, QVBoxLayout, QHBoxLayout, QLabel]:
    """.panel + .panel-h (titre 13 px, méta 11 px, 10/14 px)."""
    f = QFrame()
    f.setObjectName("panel")
    lay = QVBoxLayout(f)
    lay.setContentsMargins(1, 1, 1, 1)
    lay.setSpacing(0)
    head = QFrame()
    head.setObjectName("panelH")
    head.setFixedHeight(36)  # 185→222 sur la maquette, bordure basse comprise
    hl = QHBoxLayout(head)
    hl.setContentsMargins(14, 0, 14, 0)
    hl.setSpacing(8)
    hl.addWidget(label(title, "panelTitle"))
    hl.addStretch(1)
    m = label(meta, "meta")
    hl.addWidget(m)
    lay.addWidget(head)
    return f, lay, hl, m


def page_header(title: str, hint: str) -> QHBoxLayout:
    top = QHBoxLayout()
    top.setContentsMargins(0, 0, 0, 0)
    h1 = label(title, "h1")
    h1.setFixedHeight(20)
    top.addWidget(h1)
    top.addStretch(1)
    top.addWidget(label(hint, "hint"))
    return top


class ToggleCard(QFrame):
    """.toggle-card : titre 12/600 + sous-titre 10 px, interrupteur 40×22, état."""

    def __init__(
        self,
        title: str,
        sub: str,
        on_click: Callable[[], None],
        key: str,
        on_text: str = "ACTIVÉ",
        off_text: str = "DÉSACTIVÉ",
        off_is_good: bool = False,
    ) -> None:
        super().__init__()
        self.setObjectName("card")
        self.setToolTip(f"Raccourci clavier : {key}")
        self.on_text, self.off_text = on_text, off_text
        self.off_is_good = off_is_good
        self.setFixedHeight(83)  # 12 + 30 + 10 + 19 + 12 (maquette)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(10)
        top = QHBoxLayout()
        top.setSpacing(8)
        txt = QVBoxLayout()
        txt.setSpacing(2)
        t, sb = label(title, "cardTitle"), label(sub, "cardSub")
        t.setFixedHeight(15)
        sb.setFixedHeight(13)
        txt.addWidget(t)
        txt.addWidget(sb)
        top.addLayout(txt, 1)
        self.switch = Switch(neutral_off=off_is_good)
        self.switch.clicked.connect(lambda _c=False: on_click())
        top.addWidget(self.switch, 0, Qt.AlignmentFlag.AlignTop)
        lay.addLayout(top)
        bottom = QHBoxLayout()
        bottom.setSpacing(6)
        self.pill = QLabel()
        self.pill.setFixedHeight(19)
        bottom.addWidget(self.pill, 0, Qt.AlignmentFlag.AlignLeft)
        bottom.addStretch(1)
        self.extra = bottom
        lay.addLayout(bottom)
        self.set_state(False)

    def set_state(self, on: bool) -> None:
        self.switch.blockSignals(True)
        self.switch.setChecked(on)
        self.switch.blockSignals(False)
        self.switch.update()
        text = self.on_text if on else self.off_text
        if self.off_is_good:  # relais : « autorisé » cyan (neutre), « bloqué » rouge
            set_pill(self.pill, text, "off" if on else "info")
        else:
            set_pill(self.pill, text, "on" if on else "off")


class StatCard(QFrame):
    """.stat-card : icône 36 px rayon 10, valeur 20/700, libellé 11 px."""

    def __init__(self, icon: str, caption: str, red: bool = False) -> None:
        super().__init__()
        self.setObjectName("card")
        self.setFixedHeight(64)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(12)
        ico = label(icon, "statIco")
        ico.setFixedSize(36, 36)
        ico.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ico.setProperty("red", red)
        lay.addWidget(ico)
        col = QVBoxLayout()
        col.setSpacing(2)
        self.value = label("0", "statVal")
        self.value.setProperty("red", red)
        col.addWidget(self.value)
        self.caption = label(caption, "statLbl")
        col.addWidget(self.caption)
        lay.addLayout(col, 1)


class PlayersTable(QTableWidget):
    """Table aux largeurs de colonnes proportionnelles à la maquette."""

    def resizeEvent(self, e: QResizeEvent) -> None:
        super().resizeEvent(e)
        w = self.viewport().width()
        total = sum(COL_RATIOS)
        used = 0
        for i, r in enumerate(COL_RATIOS[:-1]):
            cw = round(w * r / total)
            self.setColumnWidth(i, cw)
            used += cw
        self.setColumnWidth(len(COL_RATIOS) - 1, max(40, w - used))


class LivePage(QWidget):
    def __init__(self, win: MainWindow) -> None:
        super().__init__()
        a = win.actions_
        self.win = win
        self._buttons: dict[int, tuple[str, bool, QPushButton]] = {}
        self._holders: dict[int, QWidget] = {}
        self.view_rows: list[Row] = []
        self.history: dict[str, deque[float]] = {}
        self._events_seen: list[str] = []
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(12)
        # .toggles : 5 colonnes égales, écart 10 px.
        toggles = QGridLayout()
        toggles.setSpacing(10)
        self.auto = ToggleCard(
            "Bouclier auto", "Détection de flood", a.toggle_auto, "A"
        )
        self.total = ToggleCard(
            "Blocage total", "Coupe tout le trafic", a.toggle_total, "T"
        )
        self.lock = ToggleCard(
            "Verrou de session", "Refuse les nouveaux", a.toggle_lock, "V"
        )
        self.rec = ToggleCard(
            "Enregistrement", "Capture post-événement", a.toggle_recording, "E"
        )
        self.kick = QPushButton("Capturer (K)")
        self.kick.setObjectName("ghost")
        self.kick.setToolTip("Boîte noire : capture des secondes avant/après un kick")
        self.kick.setStyleSheet("padding: 1px 8px; font-size: 10px;")
        self.kick.clicked.connect(lambda _c=False: a.kick_capture())
        self.rec.extra.addWidget(self.kick)
        self.relay = ToggleCard(
            "Relais Rockstar",
            "Services officiels",
            a.toggle_relay,
            "L",
            on_text="BLOQUÉ",
            off_text="AUTORISÉ",
            off_is_good=True,
        )
        for i, c in enumerate((self.auto, self.total, self.lock, self.rec, self.relay)):
            toggles.addWidget(c, 0, i)
            toggles.setColumnStretch(i, 1)
        root.addLayout(toggles)
        # .stats : 4 colonnes égales.
        stats = QGridLayout()
        stats.setSpacing(10)
        self.players = StatCard("👥", "Joueurs en session")
        self.blocked = StatCard("⊘", "Bloqués", red=True)
        self.pps = StatCard("⟳", "Paquets/s")
        self.state = StatCard("◈", "Protection")
        for i, sc in enumerate((self.players, self.blocked, self.pps, self.state)):
            stats.addWidget(sc, 0, i)
            stats.setColumnStretch(i, 1)
        root.addLayout(stats)
        # .content-row : table (1fr) + alertes 280 px, écart 12 px.
        body = QHBoxLayout()
        body.setSpacing(12)
        tp, tl, head, self.meta = panel(
            "Joueurs en session", "0 affichés · filtrage réseau uniquement"
        )
        self.b_block = QPushButton("Bloquer (B)")
        self.b_unblock = QPushButton("Débloquer (D)")
        self.b_friend = QPushButton("Ami (F)")
        self.b_pseudo = QPushButton("Pseudo (P)")
        self.b_block.clicked.connect(lambda _c=False: win.block_selected())
        self.b_unblock.clicked.connect(lambda _c=False: win.unblock_selected())
        self.b_friend.clicked.connect(lambda _c=False: win.friend_selected())
        self.b_pseudo.clicked.connect(lambda _c=False: win.pseudo_selected())
        for b in (self.b_block, self.b_unblock, self.b_friend, self.b_pseudo):
            b.setObjectName("ghost")
            b.setToolTip("Agit sur la ligne sélectionnée")
            b.setFixedHeight(20)
            b.setStyleSheet("padding: 0 8px; font-size: 10px;")
            head.addWidget(b)
        self.table = PlayersTable(0, len(COLUMNS))
        self.table.setObjectName("players")
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(ROW_H)
        self.table.verticalHeader().setMinimumSectionSize(ROW_H)
        hh = self.table.horizontalHeader()
        hh.setFixedHeight(HEAD_H)
        hh.setDefaultAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )
        hh.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        hh.setHighlightSections(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.setMouseTracking(True)
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.table.setIconSize(QSize(20, 14))
        self.table.setItemDelegate(PlayersDelegate(self))
        tl.addWidget(self.table, 1)
        legend, ll = frame("legend", vertical=False)
        ll.setContentsMargins(14, 6, 14, 8)
        ll.setSpacing(8)
        vpn = label("🔒 VPN", "vpnBadge")
        ll.addWidget(vpn)
        ll.addWidget(
            label(
                "= adresse d'un VPN ou d'un hébergeur connu (détection locale) · "
                "PAYS, PING, DEBIT = hors seuils · NOUVEAU · AMI · RÉCIDIVISTE",
                "legendText",
            ),
            1,
        )
        tl.addWidget(legend)
        # .rockstar : serveurs officiels, jamais bloqués.
        srv, sl = frame("rockstar")
        sl.setContentsMargins(12, 8, 12, 10)
        sl.setSpacing(2)
        hl = QHBoxLayout()
        hl.setSpacing(8)
        hl.addWidget(label("SERVEURS ROCKSTAR", "sectionH"))
        hl.addWidget(label("jamais bloqués", "tag"))
        hl.addStretch(1)
        sl.addLayout(hl)
        sl.addSpacing(4)
        self.servers = QTableWidget(0, 3)
        self.servers.setObjectName("servers")
        self.servers.horizontalHeader().setVisible(False)
        self.servers.verticalHeader().setVisible(False)
        self.servers.verticalHeader().setDefaultSectionSize(22)
        self.servers.setShowGrid(False)
        self.servers.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.servers.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.servers.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.servers.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.servers.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        sh = self.servers.horizontalHeader()
        sh.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        sh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        sh.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.servers.setColumnWidth(0, 150)
        self.servers.setColumnWidth(2, 80)
        self.servers.setFixedHeight(0)
        sl.addWidget(self.servers)
        self.no_servers = label(
            "Aucun serveur Rockstar vu pour l'instant.", "legendText"
        )
        sl.addWidget(self.no_servers)
        tl.addWidget(srv)
        body.addWidget(tp, 1)
        ap, al, _ah, _am = panel("Alertes", "Temps réel")
        ap.setFixedWidth(280)
        self.alerts = QListWidget()
        self.alerts.setItemDelegate(AlertDelegate(self.alerts))
        self.alerts.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.alerts.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.alerts.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.alerts.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.alerts.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.alerts.setResizeMode(QListWidget.ResizeMode.Adjust)
        self.alerts.setUniformItemSizes(False)
        box = QWidget()
        bl = QVBoxLayout(box)
        bl.setContentsMargins(10, 8, 10, 8)
        bl.addWidget(self.alerts)
        al.addWidget(box, 1)
        chart, cl = frame("chartBox")
        cl.setContentsMargins(12, 8, 12, 10)
        cl.setSpacing(4)
        ch = QHBoxLayout()
        ch.addWidget(label("TRAFIC ENTRANT (60 S)", "sectionH"))
        ch.addStretch(1)
        self.traffic_lbl = label("0 pkt/s", "chartVal")
        ch.addWidget(self.traffic_lbl)
        cl.addLayout(ch)
        self.spark = Sparkline(HISTORY)
        cl.addWidget(self.spark)
        al.addWidget(chart)
        body.addWidget(ap)
        root.addLayout(body, 1)

    # Données de présentation.
    @staticmethod
    def tags(r: Row) -> list[str]:
        tags = list(r.badges)
        if r.new:
            tags.append("NOUVEAU")
        if r.friend:
            tags.append("AMI")
        if r.recidivist:
            tags.append("RÉCIDIVISTE")
        return tags

    @staticmethod
    def status_kind(r: Row) -> str:
        if r.server:
            return "server"
        if r.blocked:
            return "blocked"
        return {0: "normal", 1: "unusual"}.get(r.level, "abnormal")

    def update_from(self, snap: Snapshot) -> None:
        self.auto.set_state(snap.auto_block)
        self.total.set_state(snap.total_block)
        self.lock.set_state(snap.session_lock)
        self.rec.set_state(snap.recording)
        self.relay.set_state(snap.relay_block)
        self.players.value.setText(str(snap.players))
        self.blocked.value.setText(str(snap.blocked))
        self.pps.value.setText(f"{snap.total_pps:.0f}")
        self.state.value.setText("Active" if snap.alive else "Arrêtée")
        self.spark.push(snap.total_pps)
        self.traffic_lbl.setText(f"{snap.total_pps:.0f} pkt/s")
        self._fill_table(snap)
        self._fill_alerts(list(snap.events))

    def _fill_alerts(self, events: list[str]) -> None:
        fresh = new_events(self._events_seen, events)
        self._events_seen = events
        if not fresh:
            return
        now = time.strftime("%H:%M:%S")
        for text in fresh:
            item = QListWidgetItem(text)
            item.setData(
                Qt.ItemDataRole.UserRole, (now, alert_color(text), alert_html(text))
            )
            self.alerts.insertItem(0, item)
        while self.alerts.count() > MAX_ALERTS:
            self.alerts.takeItem(self.alerts.count() - 1)

    def _fill_table(self, snap: Snapshot) -> None:
        t = self.table
        selected = self.selected_ip()
        players = [r for r in snap.rows if not r.server]
        for r in snap.rows:
            h = self.history.setdefault(r.ip, deque(maxlen=SPARK_BARS))
            h.append(r.pps)
        self.view_rows = players
        self.meta.setText(f"{len(players)} affichés · filtrage réseau uniquement")
        t.setUpdatesEnabled(False)
        t.setRowCount(len(players))
        for i, r in enumerate(players):
            ping = "—" if r.ping_ms is None else f"{r.ping_ms:.0f} ms"
            cells = [
                countries.name(r.country) if r.country != "—" else "Inconnu",
                r.ip,
                ping,
                f"{r.pps:.0f}",
                r.status,
            ]
            for j, text in enumerate(cells):
                item = t.item(i, j)
                if item is None:
                    item = QTableWidgetItem()
                    t.setItem(i, j, item)
                item.setText(text)
                if j == 0:
                    item.setData(Qt.ItemDataRole.UserRole, r.ip)
                    item.setIcon(flag_icon(r.country))
                    item.setToolTip(text)
                elif j == 1:
                    tags = self.tags(r)
                    item.setData(BADGES_ROLE, " ".join(tags))
                    item.setToolTip(" ".join([r.pseudo, *tags]).strip())
            self._row_button(i, r.ip, r.blocked)
            if r.ip == selected:
                t.selectRow(i)
        for i in [k for k in self._buttons if k >= len(players)]:
            del self._buttons[i]
            self._holders.pop(i, None)
        t.setUpdatesEnabled(True)
        t.viewport().update()
        servers = [r for r in snap.rows if r.server]
        self.servers.setRowCount(len(servers))
        self.servers.setFixedHeight(22 * min(len(servers), 3))
        self.no_servers.setVisible(not servers)
        for i, r in enumerate(servers):
            for j, text in enumerate((r.ip, r.status, f"{r.pps:.0f} pkt/s")):
                item = self.servers.item(i, j)
                if item is None:
                    item = QTableWidgetItem()
                    self.servers.setItem(i, j, item)
                    item.setFont(font(11, mono=j == 0))
                    item.setForeground(Qt.GlobalColor.gray)
                    if j == 2:
                        item.setTextAlignment(
                            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
                        )
                item.setText(text)

    def _row_button(self, row: int, ip: str, blocked: bool) -> None:
        """Bouton Bloquer/Débloquer de la ligne (recréé seulement si la ligne change)."""
        cur = self._buttons.get(row)
        if cur is not None and cur[0] == ip and cur[1] == blocked:
            return
        b = QPushButton("Débloquer" if blocked else "Bloquer")
        b.setObjectName("ok" if blocked else "danger")
        b.setCursor(Qt.CursorShape.PointingHandCursor)
        b.setFixedHeight(22)
        b.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        if blocked:
            b.clicked.connect(lambda _c=False, x=ip: self.win.unblock_ip(x))
        else:
            b.clicked.connect(lambda _c=False, x=ip: self.win.block_ip(x))
        holder = QWidget()
        hl = QHBoxLayout(holder)
        hl.setContentsMargins(10, 0, 4, 0)
        hl.addWidget(b, 0, Qt.AlignmentFlag.AlignVCenter)
        hl.addStretch(1)
        old = self._holders.pop(row, None)
        if old is not None:
            old.hide()
        self.table.setCellWidget(row, ACTION_COL, holder)
        self._holders[row] = holder
        self._buttons[row] = (ip, blocked, b)

    def row_button(self, ip: str) -> QPushButton | None:
        for bip, _b, btn in self._buttons.values():
            if bip == ip:
                return btn
        return None

    def selected_ip(self) -> str | None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self.table.item(rows[0].row(), 0)
        if item is None:
            return None
        ip = item.data(Qt.ItemDataRole.UserRole)
        return ip if isinstance(ip, str) else None


def plain_table(headers: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setObjectName("plain")
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.verticalHeader().setDefaultSectionSize(ROW_H)
    hh = t.horizontalHeader()
    hh.setFixedHeight(HEAD_H)
    hh.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
    hh.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    hh.setHighlightSections(False)
    t.setShowGrid(False)
    t.setWordWrap(False)
    t.setFocusPolicy(Qt.FocusPolicy.NoFocus)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    return t


class BlockedPage(QWidget):
    def __init__(self, win: MainWindow) -> None:
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)
        lay.addLayout(
            page_header(
                "Joueurs bloqués", "Débloquer : sélection puis bouton ou touche D"
            )
        )
        p, pl, head, self.meta = panel("Adresses bloquées", "")
        self.unblock = QPushButton("Débloquer la sélection (D)")
        self.unblock.setObjectName("ok")
        self.unblock.clicked.connect(lambda _c=False: self._unblock(win))
        head.addWidget(self.unblock)
        self.table = plain_table(["ADRESSE IP", "STATUT"])
        pl.addWidget(self.table, 1)
        lay.addWidget(p, 1)

    def _unblock(self, win: MainWindow) -> None:
        rows = self.table.selectionModel().selectedRows()
        if rows:
            item = self.table.item(rows[0].row(), 0)
            if item is not None:
                win.actions_.unblock(item.text())
                win.refresh()

    def update_from(self, snap: Snapshot) -> None:
        self.meta.setText(f"{len(snap.blocked_list)} bloquée(s)")
        if self.table.rowCount() == len(snap.blocked_list) and all(
            (it := self.table.item(i, 0)) is not None and it.text() == ip
            for i, (ip, _s) in enumerate(snap.blocked_list)
        ):
            for i, (_ip, st) in enumerate(snap.blocked_list):
                cell = self.table.item(i, 1)
                if cell is not None:
                    cell.setText(st)
            return
        self.table.setRowCount(len(snap.blocked_list))
        for i, (ip, st) in enumerate(snap.blocked_list):
            it = QTableWidgetItem(ip)
            it.setFont(font(11.5, mono=True))
            self.table.setItem(i, 0, it)
            self.table.setItem(i, 1, QTableWidgetItem(st))


class FriendsPage(QWidget):
    def __init__(self, win: MainWindow) -> None:
        super().__init__()
        self.win = win
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)
        lay.addLayout(page_header("Amis", "Toujours autorisés, même en mode panique"))
        p, pl, _head, self.meta = panel("Liste des amis", "")
        self.list = QListWidget()
        self.list.setObjectName("friendsList")
        pl.addWidget(self.list, 1)
        form_box, form = frame("legend", vertical=False)
        form.setContentsMargins(14, 8, 14, 10)
        form.setSpacing(8)
        self.ip = QLineEdit()
        self.ip.setPlaceholderText("Adresse IP")
        self.nick = QLineEdit()
        self.nick.setPlaceholderText("Pseudo")
        self.add = QPushButton("Ajouter")
        self.add.setObjectName("ok")
        self.remove = QPushButton("Retirer la sélection")
        self.remove.setObjectName("danger")
        self.add.clicked.connect(lambda _c=False: self._add())
        self.remove.clicked.connect(lambda _c=False: self._remove())
        for w in (self.ip, self.nick, self.add, self.remove):
            form.addWidget(w)
        self.message = label("", "legendText")
        form.addWidget(self.message, 1)
        pl.addWidget(form_box)
        lay.addWidget(p, 1)

    def _add(self) -> None:
        ok = self.win.actions_.add_friend_ip(self.ip.text(), self.nick.text())
        self.message.setText("Ami ajouté." if ok else "Adresse invalide ou refusée.")
        if ok:
            self.ip.clear()
            self.nick.clear()
        self.win.refresh()

    def _remove(self) -> None:
        item = self.list.currentItem()
        if item is not None:
            ip = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(ip, str):
                self.win.actions_.remove_friend_ip(ip)
        self.win.refresh()

    def update_from(self, snap: Snapshot) -> None:
        self.meta.setText(f"{len(snap.friends)} ami(s)")
        texts = [f"{nick}  —  {ip}" for ip, nick in snap.friends]
        if [self.list.item(i).text() for i in range(self.list.count())] == texts:
            return
        self.list.clear()
        for (ip, _n), text in zip(snap.friends, texts, strict=True):
            self.list.addItem(text)
            last = self.list.item(self.list.count() - 1)
            last.setData(Qt.ItemDataRole.UserRole, ip)


class SliderRow(QWidget):
    """.field : libellé 12 px + valeur cyan, curseur 6 px dégradé."""

    def __init__(
        self, title: str, lo: int, hi: int, unit: str, on_change: Callable[[], None]
    ) -> None:
        super().__init__()
        self.unit = unit
        # libellé 15 px + 6 px + curseur 6 px ; la poignée 14 px déborde de 4 px.
        self.setFixedHeight(31)
        lay = QGridLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setVerticalSpacing(2)
        lay.addWidget(label(title, "fieldLabel"), 0, 0)
        self.value = label("", "fieldVal")
        lay.addWidget(self.value, 0, 1, Qt.AlignmentFlag.AlignRight)
        self.slider = QSlider(Qt.Orientation.Horizontal)
        self.slider.setFixedHeight(14)
        self.slider.setRange(lo, hi)
        self.slider.valueChanged.connect(self._show)
        self.slider.sliderReleased.connect(on_change)
        self.slider.valueChanged.connect(
            lambda _v: None if self.slider.isSliderDown() else on_change()
        )
        lay.addWidget(self.slider, 1, 0, 1, 2)

    def _show(self, v: int) -> None:
        self.value.setText(f"{v} {self.unit}".strip())

    def set(self, v: float) -> None:
        self.slider.blockSignals(True)
        self.slider.setValue(int(round(v)))
        self.slider.blockSignals(False)
        self._show(self.slider.value())

    def get(self) -> int:
        return int(self.slider.value())


def set_card(icon: str, title: str, desc: str) -> tuple[QFrame, QVBoxLayout]:
    """.set-card : h3 12.5/650 + icône cyan, description 10.5 px, champs."""
    f = QFrame()
    f.setObjectName("card")
    lay = QVBoxLayout(f)
    lay.setContentsMargins(14, 12, 14, 12)
    lay.setSpacing(0)
    h = QHBoxLayout()
    h.setSpacing(8)
    ico = label(icon, "h3Ico")
    ttl = label(title, "h3")
    for w in (ico, ttl):
        w.setFixedHeight(15)
    h.addWidget(ico)
    h.addWidget(ttl, 1)
    lay.addLayout(h)
    lay.addSpacing(3)
    lay.addWidget(label(desc, "setDesc", wrap=True))
    lay.addSpacing(10)
    return f, lay


def segmented(
    names: list[str], on_click: Callable[[int], None]
) -> tuple[QFrame, list[QPushButton]]:
    f = QFrame()
    f.setObjectName("segmented")
    lay = QHBoxLayout(f)
    lay.setContentsMargins(3, 3, 3, 3)
    lay.setSpacing(0)
    buttons = []
    for i, n in enumerate(names):
        b = QPushButton(n)
        b.setObjectName("seg")
        b.setFixedHeight(29)
        b.setCheckable(True)
        b.setCursor(Qt.CursorShape.PointingHandCursor)
        b.clicked.connect(lambda _c=False, k=i: on_click(k))
        lay.addWidget(b, 1)
        buttons.append(b)
    return f, buttons


class SettingsPage(QWidget):
    """Toutes les valeurs de data.json ; appliquées immédiatement (grille 3×3)."""

    def __init__(self, win: MainWindow) -> None:
        super().__init__()
        self.win = win
        self._loading = False
        a = win.actions_
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(12)
        root.addLayout(
            page_header(
                "Réglages",
                "Les modifications s'appliquent immédiatement au filtre réseau",
            )
        )
        grid = QGridLayout()
        grid.setSpacing(10)
        for c in range(3):
            grid.setColumnStretch(c, 1)
        ch = self._changed
        f, lay = set_card(
            "🛡️",
            "Bouclier auto",
            "Bloque automatiquement les sources dont le débit de paquets dépasse "
            "le seuil pendant le délai configuré.",
        )
        self.shield_seconds = SliderRow("Délai de réaction", 1, 60, "s", ch)
        self.shield_pps = SliderRow("Seuil (paquets/s)", 20, 1000, "", ch)
        lay.addWidget(self.shield_seconds)
        lay.addSpacing(5)  # .field margin-bottom 9 px moins le débord de la poignée
        lay.addWidget(self.shield_pps)
        lay.addStretch(1)
        grid.addWidget(f, 0, 0)
        f, lay = set_card(
            "🌍",
            "Filtre pays",
            "Pays exclus du filtrage (jamais bloqués automatiquement).",
        )
        self.trusted: list[str] = []
        self.chips_box = QWidget()
        self.chips = FlowLayout(self.chips_box, gap=6)
        self.chip_buttons: dict[str, QPushButton] = {}
        self.country_in = QLineEdit()
        self.country_in.setPlaceholderText("Code (DE)")
        self.country_in.setMaxLength(2)
        self.country_in.setFixedSize(76, 26)
        self.country_in.returnPressed.connect(self._add_country)
        self.country_add = QPushButton("+ Ajouter")
        self.country_add.setObjectName("chipAdd")
        self.country_add.setCursor(Qt.CursorShape.PointingHandCursor)
        self.country_add.clicked.connect(lambda _c=False: self._add_country())
        self.chips.addWidget(self.country_in)
        self.chips.addWidget(self.country_add)
        lay.addWidget(self.chips_box)
        lay.addStretch(1)
        grid.addWidget(f, 0, 1)
        f, lay = set_card(
            "📡",
            "Filtre ping",
            "Signale ou limite les joueurs au-delà du seuil de latence.",
        )
        self.ping = SliderRow("Ping maximum", 1, 1000, "ms", ch)
        lay.addWidget(self.ping)
        lay.addStretch(1)
        grid.addWidget(f, 0, 2)
        f, lay = set_card(
            "〰",
            "Limite de débit par joueur",
            "Plafond de paquets/s autorisé pour chaque adresse avant alerte.",
        )
        self.rate = SliderRow("Limite", 1, 2000, "pkt/s", ch)
        lay.addWidget(self.rate)
        lay.addStretch(1)
        grid.addWidget(f, 1, 0)
        f, lay = set_card(
            "☁",
            "Relais Rockstar",
            "Services officiels Rockstar (auth, matchmaking) — recommandés en "
            "Autoriser.",
        )
        seg, (self.relay_allow, self.relay_block) = segmented(
            ["Autoriser", "Bloquer"], lambda k: self._relay(k == 1)
        )
        lay.addWidget(seg)
        lay.addStretch(1)
        grid.addWidget(f, 1, 1)
        f, lay = set_card(
            "🔔",
            "Récidivistes",
            "Adresses déjà bloquées qui réapparaissent dans une session.",
        )
        self.sound = SwitchRow(
            "Alerte sonore (S)",
            "Notification audio à la détection",
            lambda: self._act(a.toggle_sound),
        )
        self.cut = SwitchRow(
            "Coupure immédiate (C)",
            "Dès le 1er paquet reconnu",
            lambda: self._act(a.toggle_cut),
        )
        lay.addWidget(self.sound)
        lay.addWidget(self.cut)
        lay.addStretch(1)
        grid.addWidget(f, 1, 2)
        f, lay = set_card(
            "◎",
            "Enregistrement",
            "Conserve un extrait réseau (métadonnées) après un kick ou un crash "
            "suspect.",
        )
        self.recording = SliderRow("Fenêtre post-événement", 1, 300, "s", ch)
        lay.addWidget(self.recording)
        lay.addStretch(1)
        grid.addWidget(f, 2, 0)
        f, lay = set_card(
            "🔒",
            "VPN",
            "Détection locale des adresses appartenant à des VPN ou hébergeurs connus.",
        )
        self.vpn_flag = Switch()
        self.vpn_block = Switch()
        self.vpn_flag_row = SwitchRow(
            "Signaler les VPN",
            "Affiche un badge violet sur les IP concernées",
            badge=True,
            switch=self.vpn_flag,
        )
        self.vpn_block_row = SwitchRow(
            "Bloquer automatiquement les VPN",
            "Coupe le trafic dès qu'un VPN est reconnu",
            badge=True,
            switch=self.vpn_block,
        )
        for sw in (self.vpn_flag, self.vpn_block):
            sw.clicked.connect(lambda _c=False: self._changed())
        lay.addWidget(self.vpn_flag_row)
        lay.addWidget(self.vpn_block_row)
        lay.addStretch(1)
        grid.addWidget(f, 2, 1)
        f, lay = set_card("🌐", "Langue", "Langue des messages et des alertes.")
        seg, (self.lang_fr, self.lang_en) = segmented(
            ["Français", "English"], lambda k: self._lang("en" if k else "fr")
        )
        lay.addWidget(seg)
        lay.addStretch(1)
        grid.addWidget(f, 2, 2)
        root.addLayout(grid)
        root.addStretch(1)
        self.load(win.actions_.settings())

    def load(self, s: Settings) -> None:
        self._loading = True
        try:
            self.shield_seconds.set(s.shield_seconds)
            self.shield_pps.set(s.shield_pps)
            self.ping.set(s.ping_max_ms)
            self.rate.set(s.rate_limit_pps)
            self.recording.set(s.recording_seconds)
            self.vpn_flag_row.set_state(s.vpn_flag)
            self.vpn_block_row.set_state(s.vpn_auto_block)
            self._set_chips(s.trusted_countries)
        finally:
            self._loading = False

    def current(self) -> Settings:
        return Settings(
            trusted_countries=list(self.trusted),
            ping_max_ms=float(self.ping.get()),
            rate_limit_pps=self.rate.get(),
            shield_pps=self.shield_pps.get(),
            shield_seconds=float(self.shield_seconds.get()),
            recording_seconds=self.recording.get(),
            vpn_flag=self.vpn_flag.isChecked(),
            vpn_auto_block=self.vpn_block.isChecked(),
        )

    def _changed(self) -> None:
        if self._loading:
            return
        self.load(self.win.actions_.apply_settings(self.current()))
        self.win.show_status("Réglages enregistrés", True)

    def _set_chips(self, codes: list[str]) -> None:
        """Pastilles « drapeau Pays × » (clic = retirer), comme la maquette."""
        if codes == self.trusted and len(self.chip_buttons) == len(codes):
            return
        self.trusted = list(codes)
        for btn in self.chip_buttons.values():
            self.chips.removeWidget(btn)
            btn.deleteLater()
        self.chip_buttons = {}
        for i, code in enumerate(self.trusted):
            fixed = code in TRUSTED_DEFAULT  # toujours de confiance (règle du lot 3)
            btn = QPushButton(countries.name(code) + ("" if fixed else "  ×"))
            btn.setObjectName("chip")
            btn.setIcon(flag_icon(code))
            btn.setIconSize(QSize(14, 10))
            if fixed:
                btn.setToolTip("Pays de confiance par défaut (non retirable)")
            else:
                btn.setCursor(Qt.CursorShape.PointingHandCursor)
                btn.setToolTip(f"Retirer {countries.name(code)}")
                btn.clicked.connect(lambda _c=False, c=code: self._del_country(c))
            self.chips.insertWidget(i, btn)
            self.chip_buttons[code] = btn
        self.chips_box.updateGeometry()

    def _add_country(self) -> None:
        code = self.country_in.text().strip().upper()
        if len(code) == 2 and code.isalpha() and code.isascii():
            if code not in self.trusted:
                self.trusted = [*self.trusted, code]
                self._changed()
            self.country_in.clear()

    def _del_country(self, code: str) -> None:
        if code in self.trusted:
            self.trusted = [c for c in self.trusted if c != code]
            self._changed()

    def _relay(self, block: bool) -> None:
        self._act(lambda: self.win.actions_.set_relay_block(block))

    def _act(self, fn: Callable[[], None]) -> None:
        fn()
        self.win.refresh()

    def _lang(self, code: str) -> None:
        from util.i18n import set_language

        set_language(code)
        self.win.refresh()

    def update_from(self, snap: Snapshot) -> None:
        self.relay_allow.setChecked(not snap.relay_block)
        self.relay_block.setChecked(snap.relay_block)
        self.sound.set_state(snap.offender_sound)
        self.cut.set_state(snap.offender_drop)
        from util.i18n import get_language

        lang = get_language()
        self.lang_fr.setChecked(lang == "fr")
        self.lang_en.setChecked(lang == "en")


class NavButton(QPushButton):
    """.nav-item : 10/12 px, rayon 9, icône 18 px + 10 px + libellé 13/500."""

    def __init__(self, icon: str, text: str) -> None:
        super().__init__()
        self.setObjectName("nav")
        self.setCheckable(True)
        self.setFixedHeight(39)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAccessibleName(text)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 0, 12, 0)
        lay.setSpacing(10)
        self.ico = label(icon, "navIco")
        self.ico.setFixedWidth(18)
        self.ico.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.txt = label(text, "navText")
        for w in (self.ico, self.txt):
            w.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            lay.addWidget(w)
        lay.addStretch(1)

    def text(self) -> str:
        return self.txt.text()

    def set_active(self, on: bool) -> None:
        self.setChecked(on)
        for w in (self.ico, self.txt):
            w.setProperty("active", on)
            repolish(w)


class MainWindow(QMainWindow):
    """Fenêtre Guardian. ``session`` : BackgroundSession déjà démarrée."""

    PAGES = ["Session en direct", "Joueurs bloqués", "Amis", "Réglages"]
    ICONS = ["◉", "⊘", "♡", "⚙"]
    FOOT_LEFT = [
        " : arrêter la protection · Protection active en fond",
        " : arrêter la protection · Protection active en fond",
        " : arrêter la protection · Protection active en fond",
        " : arrêter la protection · Préférences enregistrées localement",
    ]

    def __init__(
        self,
        session: Any,
        version: str = "",
        ask_text: Callable[[QWidget, str, str], str | None] | None = None,
    ) -> None:
        super().__init__()
        self.session = session
        self.actions_ = GuiActions(session)
        self.ask_text = ask_text or _ask_text
        self.setWindowTitle(
            f"Guardian {version} — Pare-feu GTA Online".replace("  ", " ")
        )
        # 1400×860 de la maquette moins sa barre de titre (42 px) : la barre
        # native de Windows la remplace.
        self.resize(1400, 818)
        self.setStyleSheet(style.QSS)
        central = QWidget()
        central.setObjectName("root")
        main = QHBoxLayout(central)
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)
        main.addWidget(self._sidebar())
        col = QVBoxLayout()
        col.setContentsMargins(16, 14, 16, 10)
        col.setSpacing(12)
        self.stack = QStackedWidget()
        for page in (self.live, self.blocked, self.friends, self.settings):
            self.stack.addWidget(page)
        col.addWidget(self.stack, 1)
        col.addWidget(self._footer())
        main.addLayout(col, 1)
        self.setCentralWidget(central)
        self.show_page(0)
        self._status_since: tuple[str, bool] | None = None
        self._shortcuts()
        self.timer = QTimer(self)
        self.timer.setInterval(REFRESH_MS)
        self.timer.timeout.connect(self.refresh)
        self.timer.start()
        self.refresh()

    def _sidebar(self) -> QFrame:
        side = QFrame()
        side.setObjectName("sidebar")
        side.setFixedWidth(220)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(12, 16, 12, 14)
        sl.setSpacing(0)
        brand_box = QWidget()
        brand_box.setFixedHeight(54)  # 4 + 32 + 18
        brand = QHBoxLayout(brand_box)
        brand.setContentsMargins(8, 4, 8, 18)
        brand.setSpacing(10)
        mark = QLabel()
        mark.setObjectName("brandMark")
        mark.setFixedSize(32, 32)
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mark.setPixmap(shield_pixmap(18))
        brand.addWidget(mark)
        names = QVBoxLayout()
        names.setSpacing(0)
        names.addWidget(label("Guardian", "brand"))
        names.addWidget(label("PARE-FEU RÉSEAU", "brandSub"))
        brand.addLayout(names, 1)
        sl.addWidget(brand_box)
        self.live = LivePage(self)
        self.blocked = BlockedPage(self)
        self.friends = FriendsPage(self)
        self.settings = SettingsPage(self)
        self.nav: list[NavButton] = []
        for i, (name, ico) in enumerate(zip(self.PAGES, self.ICONS, strict=True)):
            b = NavButton(ico, name)
            b.clicked.connect(lambda _c=False, n=i: self.show_page(n))
            sl.addWidget(b)
            sl.addSpacing(3)
            self.nav.append(b)
        sl.addStretch(1)
        foot = QFrame()
        foot.setObjectName("sideFoot")
        fl = QVBoxLayout(foot)
        fl.setContentsMargins(0, 12, 0, 0)
        fl.setSpacing(10)
        box = QFrame()
        box.setObjectName("panicBox")
        bl = QVBoxLayout(box)
        bl.setContentsMargins(10, 2, 10, 2)
        self.panic = SwitchRow(
            "Panique (X)", "Seuls les amis passent", self.actions_.toggle_panic
        )
        self.panic.setToolTip("Raccourci clavier : X")
        bl.addWidget(self.panic)
        fl.addWidget(box)
        lang = QFrame()
        lang.setObjectName("langSwitch")
        ll = QHBoxLayout(lang)
        ll.setContentsMargins(3, 3, 3, 3)
        ll.setSpacing(0)
        self.lang_buttons: list[QPushButton] = []
        for code in ("fr", "en"):
            lb = QPushButton(code.upper())
            lb.setObjectName("langBtn")
            lb.setCheckable(True)
            lb.setCursor(Qt.CursorShape.PointingHandCursor)
            lb.clicked.connect(lambda _c=False, c=code: self.settings._lang(c))
            ll.addWidget(lb, 1)
            self.lang_buttons.append(lb)
        fl.addWidget(lang)
        self.driver = QFrame()
        self.driver.setObjectName("driver")
        dl = QHBoxLayout(self.driver)
        dl.setContentsMargins(10, 8, 10, 8)
        dl.setSpacing(8)
        self.pilot = label("● Pilote réseau : actif", "driverText")
        dl.addWidget(self.pilot, 1)
        fl.addWidget(self.driver)
        sl.addWidget(foot)
        return side

    def _footer(self) -> QWidget:
        box = QWidget()
        box.setFixedHeight(22)  # .footer : padding-top 6 + ligne 16
        foot = QHBoxLayout(box)
        foot.setContentsMargins(4, 6, 4, 0)
        foot.setSpacing(0)
        kbd = label("Q", "kbd")
        foot.addWidget(kbd)
        self.foot_left = label(self.FOOT_LEFT[0], "footer")
        foot.addWidget(self.foot_left)
        foot.addSpacing(14)
        self.status = QLabel("")
        self.status.setObjectName("statusOk")
        foot.addWidget(self.status)
        foot.addStretch(1)
        foot.addWidget(
            label(
                "● Filtrage paquets uniquement — le jeu n'est jamais modifié",
                "footerOk",
            )
        )
        return box

    def _shortcuts(self) -> None:
        a = self.actions_
        keys: dict[str, Callable[[], Any]] = {
            "A": a.toggle_auto,
            "T": a.toggle_total,
            "V": a.toggle_lock,
            "L": a.toggle_relay,
            "X": a.toggle_panic,
            "S": a.toggle_sound,
            "C": a.toggle_cut,
            "K": a.kick_capture,
            "E": a.toggle_recording,
            "B": self.block_selected,
            "D": self.unblock_selected,
            "F": self.friend_selected,
            "P": self.pseudo_selected,
        }
        self._keys = []
        for k, fn in keys.items():
            sc = QShortcut(QKeySequence(k), self)
            sc.setContext(Qt.ShortcutContext.WindowShortcut)
            sc.activated.connect(lambda f=fn: self._run(f))
            self._keys.append(sc)
        quit_ = QShortcut(QKeySequence("Q"), self)  # comme la console : Q arrête
        quit_.activated.connect(self.close)
        self._keys.append(quit_)

    def _run(self, fn: Callable[[], Any]) -> None:
        fn()
        self.refresh()

    def show_page(self, n: int) -> None:
        self.stack.setCurrentIndex(n)
        for i, b in enumerate(self.nav):
            b.set_active(i == n)
        if hasattr(self, "foot_left"):
            self.foot_left.setText(self.FOOT_LEFT[n])

    def show_status(self, text: str, ok: bool) -> None:
        """Un seul message (le dernier), vert si actif/ok, rouge sinon."""
        self.status.setText(text)
        self.status.setObjectName("statusOk" if ok else "statusBad")
        repolish(self.status)

    def refresh(self) -> None:
        try:
            snap = take_snapshot(self.session)
        except Exception:
            return
        self.live.update_from(snap)
        self.blocked.update_from(snap)
        self.friends.update_from(snap)
        self.settings.update_from(snap)
        self.panic.set_state(snap.panic)
        if snap.toggle is not None and snap.toggle != self._status_since:
            self._status_since = snap.toggle
            self.show_status(*snap.toggle)
        elif snap.toggle is None and self._status_since is not None:
            self._status_since = None
            self.status.setText("")
        self.pilot.setText(
            "● Pilote réseau : actif" if snap.alive else "● Pilote réseau : arrêté"
        )
        for w in (self.pilot, self.driver):
            if w.property("bad") != (not snap.alive):
                w.setProperty("bad", not snap.alive)
                repolish(w)
        for b, on in zip(
            self.lang_buttons,
            (self.settings.lang_fr.isChecked(), self.settings.lang_en.isChecked()),
            strict=True,
        ):
            b.setChecked(on)

    # Actions sur la ligne sélectionnée.
    def block_ip(self, ip: str) -> None:
        pseudo = self.ask_text(self, "Bloquer", f"Pseudo pour {ip} (facultatif) :")
        if pseudo is not None:
            self.actions_.block(ip, pseudo)
        self.refresh()

    def unblock_ip(self, ip: str) -> None:
        self.actions_.unblock(ip)
        self.refresh()

    def block_selected(self) -> None:
        ip = self.live.selected_ip()
        if ip is None:
            return
        self.block_ip(ip)

    def unblock_selected(self) -> None:
        ip = self.live.selected_ip()
        if ip is not None:
            self.actions_.unblock(ip)
        else:
            self.show_page(1)
        self.refresh()

    def friend_selected(self) -> None:
        ip = self.live.selected_ip()
        if ip is None:
            self.show_page(2)
            return
        nick = ""
        if not self.session.ctrl.is_friend(ip):
            answer = self.ask_text(self, "Ami", f"Pseudo de l'ami {ip} :")
            if answer is None:
                return
            nick = answer
        self.actions_.toggle_friend(ip, nick)
        self.refresh()

    def pseudo_selected(self) -> None:
        ip = self.live.selected_ip()
        if ip is None:
            return
        answer = self.ask_text(self, "Pseudo", f"Pseudo pour {ip} :")
        if answer is not None:
            self.actions_.set_pseudo(ip, answer)
        self.refresh()


def _ask_text(parent: QWidget, title: str, text: str) -> str | None:
    value, ok = QInputDialog.getText(parent, title, text)
    return value if ok else None
