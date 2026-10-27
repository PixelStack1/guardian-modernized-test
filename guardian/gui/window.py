"""Fenêtre principale PySide6. Lecture par QTimer, jamais dans la capture."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QPointF, QSize, Qt, QTimer
from PySide6.QtGui import (
    QColor,
    QIcon,
    QKeySequence,
    QPainter,
    QPaintEvent,
    QPen,
    QPixmap,
    QShortcut,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QPushButton,
    QSlider,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gui import countries, style
from gui.core import GuiActions, Settings, Snapshot, take_snapshot
from network.filters import TRUSTED_DEFAULT

REFRESH_MS = 500
HISTORY = 120  # 60 s à 500 ms

LEVEL_COLORS = {0: style.GREEN, 1: style.ORANGE, 2: style.RED}
COLUMNS = [
    "PAYS",
    "ADRESSE IP",
    "PING",
    "PAQUETS/S",
    "STATUT",
    "BADGES",
    "PSEUDO",
    "ACTION",
]
ACTION_COL = 7
_FLAGS: dict[str, QIcon] = {}


def flag_icon(code: str) -> QIcon:
    """Petit drapeau dessiné localement (bandes) ; code en pastille sinon."""
    icon = _FLAGS.get(code)
    if icon is not None:
        return icon
    pm = QPixmap(20, 14)
    pm.fill(QColor("#2a3550"))
    p = QPainter(pm)
    spec = countries.STRIPES.get(code)
    if spec is not None:
        orient, colors = spec
        n = len(colors)
        for i, c in enumerate(colors):
            if orient == "v":
                x0, x1 = 20 * i // n, 20 * (i + 1) // n
                p.fillRect(x0, 0, x1 - x0, 14, QColor(c))
            else:
                y0, y1 = 14 * i // n, 14 * (i + 1) // n
                p.fillRect(0, y0, 20, y1 - y0, QColor(c))
        if code == "CH":
            p.fillRect(8, 3, 4, 8, QColor("white"))
            p.fillRect(6, 5, 8, 4, QColor("white"))
        elif code == "JP":
            p.setBrush(QColor("#bc002d"))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(6, 3, 8, 8)
        elif code == "TR":
            p.setBrush(QColor("white"))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(4, 3, 8, 8)
            p.setBrush(QColor("#e30a17"))
            p.drawEllipse(6, 4, 7, 6)
    else:
        p.setPen(QColor(style.MUTED))
        f = p.font()
        f.setPixelSize(8)
        p.setFont(f)
        p.drawText(pm.rect(), Qt.AlignmentFlag.AlignCenter, code[:2] or "?")
    p.end()
    icon = QIcon(pm)
    _FLAGS[code] = icon
    return icon


def card(parent: QWidget | None = None) -> tuple[QFrame, QVBoxLayout]:
    f = QFrame(parent)
    f.setObjectName("card")
    lay = QVBoxLayout(f)
    lay.setContentsMargins(12, 10, 12, 10)
    lay.setSpacing(4)
    return f, lay


def label(text: str, name: str = "") -> QLabel:
    lab = QLabel(text)
    if name:
        lab.setObjectName(name)
    lab.setWordWrap(True)
    return lab


def set_pill(
    lab: QLabel, on: bool, on_text: str = "ACTIVÉ", off: str = "DÉSACTIVÉ"
) -> None:
    lab.setText(on_text if on else off)
    lab.setObjectName("pillOn" if on else "pillOff")
    lab.style().unpolish(lab)
    lab.style().polish(lab)


class ToggleCard(QFrame):
    """Carte titre + interrupteur + pastille d'état (vert/rouge)."""

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
        self.on_text, self.off_text = on_text, off_text
        self.off_is_good = off_is_good
        lay = QGridLayout(self)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.addWidget(label(f"{title}  ({key})", "cardTitle"), 0, 0)
        lay.addWidget(label(sub, "cardSub"), 1, 0)
        self.switch = QCheckBox()
        self.switch.setObjectName("switch")
        self.switch.setFixedSize(38, 22)
        self.switch.setCursor(Qt.CursorShape.PointingHandCursor)
        self.switch.clicked.connect(lambda _c=False: on_click())
        lay.addWidget(self.switch, 0, 1, 2, 1, Qt.AlignmentFlag.AlignRight)
        self.pill = QLabel()
        lay.addWidget(self.pill, 2, 0, Qt.AlignmentFlag.AlignLeft)
        self.extra = QHBoxLayout()
        lay.addLayout(self.extra, 2, 1)
        self.set_state(False)

    def set_state(self, on: bool) -> None:
        self.switch.blockSignals(True)
        self.switch.setChecked(on)
        self.switch.blockSignals(False)
        set_pill(self.pill, on, self.on_text, self.off_text)
        if (
            self.off_is_good
        ):  # relais : « autorisé » (défaut) en vert, « bloqué » en rouge
            self.pill.setObjectName("pillOff" if on else "pillOn")
            self.pill.style().unpolish(self.pill)
            self.pill.style().polish(self.pill)


class StatCard(QFrame):
    def __init__(self, caption: str, red: bool = False) -> None:
        super().__init__()
        self.setObjectName("card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        self.value = label("0", "bigRed" if red else "big")
        lay.addWidget(self.value)
        lay.addWidget(label(caption, "cardSub"))


class Sparkline(QWidget):
    """Trafic entrant des 60 dernières secondes."""

    def __init__(self) -> None:
        super().__init__()
        self.values: deque[float] = deque(maxlen=HISTORY)
        self.setMinimumHeight(48)

    def push(self, v: float) -> None:
        self.values.append(v)
        self.update()

    def paintEvent(self, _e: QPaintEvent) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor(style.PANEL))
        vals = list(self.values)
        if len(vals) >= 2:
            top = max(vals) or 1.0
            w, h = self.width(), self.height() - 4
            step = w / (HISTORY - 1)
            x0 = w - step * (len(vals) - 1)
            pts = [
                QPointF(x0 + i * step, 2 + h - h * v / top) for i, v in enumerate(vals)
            ]
            p.setPen(QPen(QColor(style.CYAN), 1.5))
            p.drawPolyline(pts)
        p.end()


class LivePage(QWidget):
    def __init__(self, win: MainWindow) -> None:
        super().__init__()
        a = win.actions_
        self.win = win
        self._buttons: dict[int, tuple[str, bool, QPushButton]] = {}
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)
        row = QHBoxLayout()
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
            "Enregistrement", "Métadonnées / capture", a.toggle_recording, "E"
        )
        self.kick = QPushButton("Capturer (K)")
        self.kick.setToolTip("Boîte noire : capture des secondes avant/après")
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
        for c in (self.auto, self.total, self.lock, self.rec, self.relay):
            row.addWidget(c)
        root.addLayout(row)
        row2 = QHBoxLayout()
        self.panic = ToggleCard(
            "Panique", "Seuls les amis passent", a.toggle_panic, "X"
        )
        self.sound = ToggleCard("Son récidiviste", "Alerte sonore", a.toggle_sound, "S")
        self.cut = ToggleCard(
            "Coupure immédiate", "Récidiviste coupé au 1er paquet", a.toggle_cut, "C"
        )
        for c in (self.panic, self.sound, self.cut):
            row2.addWidget(c)
        root.addLayout(row2)
        stats = QHBoxLayout()
        self.players = StatCard("Joueurs en session")
        self.blocked = StatCard("Bloqués", red=True)
        self.pps = StatCard("Paquets/s")
        self.state = StatCard("Protection")
        for sc in (self.players, self.blocked, self.pps, self.state):
            stats.addWidget(sc)
        root.addLayout(stats)
        body = QHBoxLayout()
        left = QVBoxLayout()
        head = QHBoxLayout()
        head.addWidget(label("Joueurs en session", "cardTitle"))
        head.addStretch(1)
        self.b_block = QPushButton("Bloquer (B)")
        self.b_block.setObjectName("danger")
        self.b_unblock = QPushButton("Débloquer (D)")
        self.b_unblock.setObjectName("ok")
        self.b_friend = QPushButton("Ami (F)")
        self.b_pseudo = QPushButton("Pseudo (P)")
        self.b_block.clicked.connect(lambda _c=False: win.block_selected())
        self.b_unblock.clicked.connect(lambda _c=False: win.unblock_selected())
        self.b_friend.clicked.connect(lambda _c=False: win.friend_selected())
        self.b_pseudo.clicked.connect(lambda _c=False: win.pseudo_selected())
        for b in (self.b_block, self.b_unblock, self.b_friend, self.b_pseudo):
            head.addWidget(b)
        left.addLayout(head)
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.table.setShowGrid(False)
        self.table.setIconSize(QSize(20, 14))
        left.addWidget(self.table, 1)
        left.addWidget(
            label(
                "Badges : PAYS = hors pays de confiance · PING = latence élevée · "
                "DEBIT = débit élevé · VPN = VPN/hébergeur (détection locale) · "
                "NOUVEAU · AMI · RÉCIDIVISTE",
                "cardSub",
            )
        )
        # Bloc séparé « Serveurs Rockstar » (maquette) : jamais bloqués.
        srv, sl = card()
        hl = QHBoxLayout()
        hl.addWidget(label("SERVEURS ROCKSTAR", "cardSub"))
        never = QLabel("jamais bloqués")
        never.setObjectName("pillInfo")
        hl.addWidget(never)
        hl.addStretch(1)
        sl.addLayout(hl)
        self.servers = QTableWidget(0, 3)
        self.servers.horizontalHeader().setVisible(False)
        self.servers.verticalHeader().setVisible(False)
        self.servers.setShowGrid(False)
        self.servers.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.servers.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.servers.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.servers.setMaximumHeight(96)
        sl.addWidget(self.servers)
        self.no_servers = label("Aucun serveur Rockstar vu pour l'instant.", "cardSub")
        sl.addWidget(self.no_servers)
        left.addWidget(srv)
        body.addLayout(left, 3)
        right = QVBoxLayout()
        right.addWidget(label("Alertes", "cardTitle"))
        self.alerts = QListWidget()
        self.alerts.setWordWrap(True)
        self.alerts.setSpacing(3)
        right.addWidget(self.alerts, 1)
        self.traffic_lbl = label("TRAFIC ENTRANT (60 S)", "cardSub")
        right.addWidget(self.traffic_lbl)
        self.spark = Sparkline()
        right.addWidget(self.spark)
        body.addLayout(right, 1)
        root.addLayout(body, 1)

    def update_from(self, snap: Snapshot) -> None:
        self.auto.set_state(snap.auto_block)
        self.total.set_state(snap.total_block)
        self.lock.set_state(snap.session_lock)
        self.rec.set_state(snap.recording)
        self.relay.set_state(snap.relay_block)
        self.panic.set_state(snap.panic)
        self.sound.set_state(snap.offender_sound)
        self.cut.set_state(snap.offender_drop)
        self.players.value.setText(str(snap.players))
        self.blocked.value.setText(str(snap.blocked))
        self.pps.value.setText(f"{snap.total_pps:.0f}")
        self.state.value.setText("Active" if snap.alive else "Arrêtée")
        self.spark.push(snap.total_pps)
        self.traffic_lbl.setText(f"TRAFIC ENTRANT (60 S) — {snap.total_pps:.0f} pkt/s")
        self._fill_table(snap)
        events = list(reversed(snap.events))
        if [self.alerts.item(i).text() for i in range(self.alerts.count())] != events:
            self.alerts.clear()
            self.alerts.addItems(events)

    def _fill_table(self, snap: Snapshot) -> None:
        t = self.table
        selected = self.selected_ip()
        players = [r for r in snap.rows if not r.server]
        t.setUpdatesEnabled(False)
        t.setRowCount(len(players))
        for i, r in enumerate(players):
            tags = list(r.badges)
            if r.new:
                tags.append("NOUVEAU")
            if r.friend:
                tags.append("AMI")
            if r.recidivist:
                tags.append("RÉCIDIVISTE")
            ping = "—" if r.ping_ms is None else f"{r.ping_ms:.0f} ms"
            cells = [
                countries.name(r.country) if r.country != "—" else "Inconnu",
                r.label,
                ping,
                f"{r.pps:.0f}",
                r.status,
                " ".join(tags),
                r.pseudo,
            ]
            color = style.RED if r.blocked else LEVEL_COLORS.get(r.level, style.TEXT)
            for j, text in enumerate(cells):
                item = t.item(i, j)
                if item is None:
                    item = QTableWidgetItem()
                    t.setItem(i, j, item)
                item.setText(text)
                if j == 0:
                    item.setData(Qt.ItemDataRole.UserRole, r.ip)
                    item.setIcon(flag_icon(r.country))
                if j == 4:
                    item.setForeground(QColor(color))
                elif j == 5:
                    item.setForeground(
                        QColor(style.VIOLET if "VPN" in tags else style.ORANGE)
                    )
                else:
                    item.setForeground(QColor(style.TEXT))
            self._row_button(i, r.ip, r.blocked)
            if r.ip == selected:
                t.selectRow(i)
        for i in [k for k in self._buttons if k >= len(players)]:
            del self._buttons[i]
        t.setUpdatesEnabled(True)
        servers = [r for r in snap.rows if r.server]
        self.servers.setRowCount(len(servers))
        self.no_servers.setVisible(not servers)
        for i, r in enumerate(servers):
            for j, text in enumerate((r.ip, r.status, f"{r.pps:.0f} pkt/s")):
                item = self.servers.item(i, j)
                if item is None:
                    item = QTableWidgetItem()
                    self.servers.setItem(i, j, item)
                item.setText(text)
                item.setForeground(QColor(style.CYAN if j == 0 else style.MUTED))

    def _row_button(self, row: int, ip: str, blocked: bool) -> None:
        """Bouton Bloquer/Débloquer de la ligne (recréé seulement si la ligne change)."""
        cur = self._buttons.get(row)
        if cur is not None and cur[0] == ip and cur[1] == blocked:
            return
        b = QPushButton("Débloquer" if blocked else "Bloquer")
        b.setObjectName("ok" if blocked else "danger")
        b.setCursor(Qt.CursorShape.PointingHandCursor)
        if blocked:
            b.clicked.connect(lambda _c=False, x=ip: self.win.unblock_ip(x))
        else:
            b.clicked.connect(lambda _c=False, x=ip: self.win.block_ip(x))
        self.table.setCellWidget(row, ACTION_COL, b)
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


class BlockedPage(QWidget):
    def __init__(self, win: MainWindow) -> None:
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.addWidget(label("Joueurs bloqués", "big"))
        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["ADRESSE IP", "STATUT"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        lay.addWidget(self.table, 1)
        self.unblock = QPushButton("Débloquer la sélection (D)")
        self.unblock.setObjectName("ok")
        self.unblock.clicked.connect(lambda _c=False: self._unblock(win))
        lay.addWidget(self.unblock, 0, Qt.AlignmentFlag.AlignLeft)

    def _unblock(self, win: MainWindow) -> None:
        rows = self.table.selectionModel().selectedRows()
        if rows:
            item = self.table.item(rows[0].row(), 0)
            if item is not None:
                win.actions_.unblock(item.text())
                win.refresh()

    def update_from(self, snap: Snapshot) -> None:
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
            self.table.setItem(i, 0, QTableWidgetItem(ip))
            self.table.setItem(i, 1, QTableWidgetItem(st))


class FriendsPage(QWidget):
    def __init__(self, win: MainWindow) -> None:
        super().__init__()
        self.win = win
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.addWidget(label("Amis (toujours autorisés, même en panique)", "big"))
        self.list = QListWidget()
        lay.addWidget(self.list, 1)
        form = QHBoxLayout()
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
        lay.addLayout(form)
        self.message = label("", "cardSub")
        lay.addWidget(self.message)

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
        texts = [f"{nick}  —  {ip}" for ip, nick in snap.friends]
        if [self.list.item(i).text() for i in range(self.list.count())] == texts:
            return
        self.list.clear()
        for (ip, _n), text in zip(snap.friends, texts, strict=True):
            self.list.addItem(text)
            last = self.list.item(self.list.count() - 1)
            last.setData(Qt.ItemDataRole.UserRole, ip)


class SliderRow(QWidget):
    def __init__(
        self, title: str, lo: int, hi: int, unit: str, on_change: Callable[[], None]
    ) -> None:
        super().__init__()
        self.unit = unit
        lay = QGridLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(QLabel(title), 0, 0)
        self.value = QLabel()
        self.value.setStyleSheet(f"color: {style.CYAN}; font-weight: 600;")
        lay.addWidget(self.value, 0, 1, Qt.AlignmentFlag.AlignRight)
        self.slider = QSlider(Qt.Orientation.Horizontal)
        self.slider.setRange(lo, hi)
        self.slider.valueChanged.connect(self._show)
        self.slider.sliderReleased.connect(on_change)
        self.slider.valueChanged.connect(
            lambda _v: None if self.slider.isSliderDown() else on_change()
        )
        lay.addWidget(self.slider, 1, 0, 1, 2)

    def _show(self, v: int) -> None:
        self.value.setText(f"{v} {self.unit}")

    def set(self, v: float) -> None:
        self.slider.blockSignals(True)
        self.slider.setValue(int(round(v)))
        self.slider.blockSignals(False)
        self._show(self.slider.value())

    def get(self) -> int:
        return int(self.slider.value())


class SettingsPage(QWidget):
    """Toutes les valeurs de data.json ; appliquées immédiatement."""

    def __init__(self, win: MainWindow) -> None:
        super().__init__()
        self.win = win
        self._loading = False
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        top = QHBoxLayout()
        top.addWidget(label("Réglages", "big"))
        top.addStretch(1)
        top.addWidget(
            label(
                "Les modifications s'appliquent immédiatement au filtre réseau",
                "cardSub",
            )
        )
        root.addLayout(top)
        grid = QGridLayout()
        grid.setSpacing(10)
        ch = self._changed
        # Bouclier auto
        f, lay = card()
        lay.addWidget(label("Bouclier auto", "cardTitle"))
        lay.addWidget(
            label(
                "Bloque les sources dont le débit dépasse le seuil "
                "pendant le délai configuré.",
                "cardSub",
            )
        )
        self.shield_seconds = SliderRow("Délai de réaction", 1, 60, "s", ch)
        self.shield_pps = SliderRow("Seuil (paquets/s)", 20, 1000, "", ch)
        lay.addWidget(self.shield_seconds)
        lay.addWidget(self.shield_pps)
        grid.addWidget(f, 0, 0)
        # Filtre pays
        f, lay = card()
        lay.addWidget(label("Filtre pays", "cardTitle"))
        lay.addWidget(label("Pays de confiance : jamais signalés « PAYS ».", "cardSub"))
        self.trusted: list[str] = []
        self.chips_box = QWidget()
        self.chips = QGridLayout(self.chips_box)
        self.chips.setContentsMargins(0, 0, 0, 0)
        self.chips.setSpacing(6)
        self.chip_buttons: dict[str, QPushButton] = {}
        lay.addWidget(self.chips_box)
        r = QHBoxLayout()
        self.country_in = QLineEdit()
        self.country_in.setPlaceholderText("Code pays (ex. DE)")
        self.country_in.setMaxLength(2)
        self.country_in.setMaximumWidth(150)
        self.country_in.returnPressed.connect(self._add_country)
        self.country_add = QPushButton("+ Ajouter")
        self.country_add.setObjectName("chipAdd")
        self.country_add.clicked.connect(lambda _c=False: self._add_country())
        r.addWidget(self.country_in)
        r.addWidget(self.country_add)
        r.addStretch(1)
        lay.addLayout(r)
        grid.addWidget(f, 0, 1)
        # Ping
        f, lay = card()
        lay.addWidget(label("Filtre ping", "cardTitle"))
        lay.addWidget(
            label(
                "Signale les joueurs au-delà du seuil de latence (estimée).", "cardSub"
            )
        )
        self.ping = SliderRow("Ping maximum", 1, 1000, "ms", ch)
        lay.addWidget(self.ping)
        grid.addWidget(f, 0, 2)
        # Débit
        f, lay = card()
        lay.addWidget(label("Limite de débit par joueur", "cardTitle"))
        lay.addWidget(label("Paquets/s autorisés par adresse avant alerte.", "cardSub"))
        self.rate = SliderRow("Limite", 1, 2000, "pkt/s", ch)
        lay.addWidget(self.rate)
        grid.addWidget(f, 1, 0)
        # Relais
        f, lay = card()
        lay.addWidget(label("Relais Rockstar (L)", "cardTitle"))
        lay.addWidget(
            label("Services officiels Rockstar — recommandé : Autoriser.", "cardSub")
        )
        seg = QHBoxLayout()
        self.relay_allow = QPushButton("Autoriser")
        self.relay_block = QPushButton("Bloquer")
        for b in (self.relay_allow, self.relay_block):
            b.setObjectName("seg")
            b.setCheckable(True)
            seg.addWidget(b)
        self.relay_allow.clicked.connect(lambda _c=False: self._relay(False))
        self.relay_block.clicked.connect(lambda _c=False: self._relay(True))
        lay.addLayout(seg)
        grid.addWidget(f, 1, 1)
        # Récidivistes
        f, lay = card()
        lay.addWidget(label("Récidivistes", "cardTitle"))
        lay.addWidget(label("Adresses déjà bloquées qui réapparaissent.", "cardSub"))
        self.sound = QCheckBox("Alerte sonore (S)")
        self.cut = QCheckBox("Coupure immédiate (C)")
        for c in (self.sound, self.cut):
            c.setObjectName("switch")
            lay.addWidget(c)
        self.sound.clicked.connect(
            lambda _c=False: self._act(win.actions_.toggle_sound)
        )
        self.cut.clicked.connect(lambda _c=False: self._act(win.actions_.toggle_cut))
        grid.addWidget(f, 1, 2)
        # Enregistrement
        f, lay = card()
        lay.addWidget(label("Enregistrement", "cardTitle"))
        lay.addWidget(
            label(
                "Boîte noire : extrait réseau (métadonnées) autour d'un kick (K).",
                "cardSub",
            )
        )
        self.recording = SliderRow("Fenêtre post-événement", 1, 300, "s", ch)
        lay.addWidget(self.recording)
        grid.addWidget(f, 2, 0)
        # VPN
        f, lay = card()
        lay.addWidget(label("VPN", "cardTitle"))
        lay.addWidget(
            label("Détection locale des VPN et hébergeurs connus.", "cardSub")
        )
        self.vpn_flag = QCheckBox("Signaler les VPN")
        self.vpn_block = QCheckBox("Bloquer automatiquement les VPN")
        for c in (self.vpn_flag, self.vpn_block):
            c.setObjectName("switch")
            c.clicked.connect(lambda _c=False: self._changed())
            lay.addWidget(c)
        grid.addWidget(f, 2, 1)
        # Langue
        f, lay = card()
        lay.addWidget(label("Langue", "cardTitle"))
        lay.addWidget(
            label("Langue des messages (l'interface est en français).", "cardSub")
        )
        seg = QHBoxLayout()
        self.lang_fr = QPushButton("Français")
        self.lang_en = QPushButton("English")
        for b, code in ((self.lang_fr, "fr"), (self.lang_en, "en")):
            b.setObjectName("seg")
            b.setCheckable(True)
            b.clicked.connect(lambda _c=False, c=code: self._lang(c))
            seg.addWidget(b)
        lay.addLayout(seg)
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
            self.vpn_flag.setChecked(s.vpn_flag)
            self.vpn_block.setChecked(s.vpn_auto_block)
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
            if fixed:
                btn.setToolTip("Pays de confiance par défaut (non retirable)")
            else:
                btn.setToolTip(f"Retirer {countries.name(code)}")
                btn.clicked.connect(lambda _c=False, c=code: self._del_country(c))
            self.chips.addWidget(btn, i // 3, i % 3)
            self.chip_buttons[code] = btn

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
        for c, on in (
            (self.sound, snap.offender_sound),
            (self.cut, snap.offender_drop),
        ):
            c.blockSignals(True)
            c.setChecked(on)
            c.blockSignals(False)
        from util.i18n import get_language

        lang = get_language()
        self.lang_fr.setChecked(lang == "fr")
        self.lang_en.setChecked(lang == "en")


class MainWindow(QMainWindow):
    """Fenêtre Guardian. ``session`` : BackgroundSession déjà démarrée."""

    PAGES = ["Session en direct", "Joueurs bloqués", "Amis", "Réglages"]

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
        self.resize(1400, 860)
        self.setStyleSheet(style.QSS)
        central = QWidget()
        outer = QVBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        main = QHBoxLayout()
        main.setSpacing(0)
        side = QFrame()
        side.setObjectName("sidebar")
        side.setFixedWidth(210)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(12, 16, 12, 12)
        sl.addWidget(label("Guardian", "brand"))
        sl.addWidget(label("PARE-FEU RÉSEAU", "brandSub"))
        sl.addSpacing(14)
        self.stack = QStackedWidget()
        self.live = LivePage(self)
        self.blocked = BlockedPage(self)
        self.friends = FriendsPage(self)
        self.settings = SettingsPage(self)
        self.nav: list[QPushButton] = []
        for i, (name, page) in enumerate(
            zip(
                self.PAGES,
                (self.live, self.blocked, self.friends, self.settings),
                strict=True,
            )
        ):
            self.stack.addWidget(page)
            b = QPushButton(name)
            b.setObjectName("nav")
            b.setCheckable(True)
            b.clicked.connect(lambda _c=False, n=i: self.show_page(n))
            sl.addWidget(b)
            self.nav.append(b)
        sl.addStretch(1)
        self.pilot = label("● Pilote réseau : actif", "footerOk")
        sl.addWidget(self.pilot)
        main.addWidget(side)
        main.addWidget(self.stack, 1)
        outer.addLayout(main, 1)
        foot = QHBoxLayout()
        foot.setContentsMargins(14, 6, 14, 8)
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
        outer.addLayout(foot)
        self.setCentralWidget(central)
        self.show_page(0)
        self._status_since: tuple[str, bool] | None = None
        self._shortcuts()
        self.timer = QTimer(self)
        self.timer.setInterval(REFRESH_MS)
        self.timer.timeout.connect(self.refresh)
        self.timer.start()
        self.refresh()

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

    def _run(self, fn: Callable[[], Any]) -> None:
        fn()
        self.refresh()

    def show_page(self, n: int) -> None:
        self.stack.setCurrentIndex(n)
        for i, b in enumerate(self.nav):
            b.setChecked(i == n)

    def show_status(self, text: str, ok: bool) -> None:
        """Un seul message (le dernier), vert si actif/ok, rouge sinon."""
        self.status.setText(text)
        self.status.setObjectName("statusOk" if ok else "statusBad")
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)

    def refresh(self) -> None:
        try:
            snap = take_snapshot(self.session)
        except Exception:
            return
        self.live.update_from(snap)
        self.blocked.update_from(snap)
        self.friends.update_from(snap)
        self.settings.update_from(snap)
        if snap.toggle is not None and snap.toggle != self._status_since:
            self._status_since = snap.toggle
            self.show_status(*snap.toggle)
        elif snap.toggle is None and self._status_since is not None:
            self._status_since = None
            self.status.setText("")
        self.pilot.setText(
            "● Pilote réseau : actif" if snap.alive else "● Pilote réseau : arrêté"
        )
        self.pilot.setObjectName("footerOk" if snap.alive else "statusBad")

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
        pseudo = self.ask_text(self, "Bloquer", f"Pseudo pour {ip} (facultatif) :")
        if pseudo is not None:
            self.actions_.block(ip, pseudo)
        self.refresh()

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
