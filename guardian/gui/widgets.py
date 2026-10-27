"""Briques visuelles reprises de la maquette (interrupteur, délégués, flux…)."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import (
    QModelIndex,
    QPersistentModelIndex,
    QPoint,
    QPointF,
    QRect,
    QRectF,
    QSize,
    Qt,
)
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QFontMetrics,
    QIcon,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPaintEvent,
    QPen,
    QPixmap,
    QTextBlockFormat,
    QTextCursor,
    QTextDocument,
)
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLayout,
    QLayoutItem,
    QListWidget,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QVBoxLayout,
    QWidget,
    QWidgetItem,
)

from gui import countries, style

FONT_FAMILIES = ["Segoe UI", "Selawik", "Inter", "DejaVu Sans"]
MONO_FAMILIES = ["Consolas", "Cascadia Mono", "DejaVu Sans Mono"]
ROW_H = 37  # tbody td : 7 px + bouton 22 px + 7 px + bordure
HEAD_H = 27  # thead th : 7 px + 10 px + 7 px + bordure
_FLAGS: dict[str, QIcon] = {}


def font(px: float, weight: int = 400, mono: bool = False) -> QFont:
    f = QFont()
    f.setFamilies(MONO_FAMILIES if mono else FONT_FAMILIES)
    f.setPixelSize(max(1, round(px)))
    f.setWeight(QFont.Weight(weight))
    return f


def repolish(w: QWidget) -> None:
    w.style().unpolish(w)
    w.style().polish(w)


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
        p.setFont(font(8))
        p.drawText(pm.rect(), Qt.AlignmentFlag.AlignCenter, code[:2] or "?")
    p.end()
    icon = QIcon(pm)
    _FLAGS[code] = icon
    return icon


def shield_pixmap(size: int = 18) -> QPixmap:
    """Bouclier coché de la marque (même tracé SVG que la maquette, 24×24)."""
    pm = QPixmap(size * 2, size * 2)
    pm.setDevicePixelRatio(2.0)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.scale(size / 24, size / 24)
    shield = QPainterPath(QPointF(12, 2))
    shield.lineTo(20, 5.5)
    shield.lineTo(20, 12)
    shield.cubicTo(20, 17, 16.5, 20.5, 12, 22)
    shield.cubicTo(7.5, 20.5, 4, 17, 4, 12)
    shield.lineTo(4, 5.5)
    shield.closeSubpath()
    p.setBrush(QColor(61, 214, 255, 38))
    p.setPen(QPen(QColor(style.CYAN), 1.6))
    p.drawPath(shield)
    pen = QPen(QColor(style.CYAN), 1.8)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawPolyline([QPointF(9, 12), QPointF(11, 14), QPointF(15, 9)])
    p.end()
    return pm


def label(text: str, name: str = "", wrap: bool = False) -> QLabel:
    lab = QLabel(text)
    if name:
        lab.setObjectName(name)
    lab.setWordWrap(wrap)
    return lab


def frame(name: str, vertical: bool = True) -> tuple[QFrame, QVBoxLayout | QHBoxLayout]:
    f = QFrame()
    f.setObjectName(name)
    lay: QVBoxLayout | QHBoxLayout = QVBoxLayout(f) if vertical else QHBoxLayout(f)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(0)
    return f, lay


def set_pill(lab: QLabel, text: str, kind: str) -> None:
    """kind : on (vert), off (rouge), info (cyan) — .badge-state de la maquette."""
    lab.setText(text)
    lab.setObjectName({"on": "pillOn", "off": "pillOff"}.get(kind, "pillInfo"))
    repolish(lab)


class Switch(QCheckBox):
    """Interrupteur .pill 40×22 (on vert lumineux, off rouge, neutre cyan)."""

    def __init__(self, neutral_off: bool = False) -> None:
        super().__init__()
        self.neutral_off = neutral_off
        self.setObjectName("switch")
        self.setFixedSize(40, 22)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def hitButton(self, pos: QPoint) -> bool:
        return self.rect().contains(pos)

    def paintEvent(self, _e: QPaintEvent) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(0.5, 0.5, 39, 21)
        on = self.isChecked()
        neutral = self.neutral_off and not on
        if on:
            g = QLinearGradient(0, 0, 40, 0)
            g.setColorAt(0, QColor("#1dbf7a"))
            g.setColorAt(1, QColor(style.GREEN))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(g))
            knob, kx = QColor("white"), 22.0
        elif neutral:
            p.setPen(QPen(QColor(61, 214, 255, 77), 1))
            p.setBrush(QColor(61, 214, 255, 51))
            knob, kx = QColor("#c8f0ff"), 22.0
        else:
            p.setPen(QPen(QColor(255, 92, 108, 89), 1))
            p.setBrush(QColor(255, 92, 108, 64))
            knob, kx = QColor("#ffb0b8"), 3.0
        p.drawRoundedRect(r, 11, 11)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(0, 0, 0, 70))
        p.drawEllipse(QRectF(kx, 4, 16, 16))
        p.setBrush(knob)
        p.drawEllipse(QRectF(kx, 3, 16, 16))
        p.end()


class FlowLayout(QLayout):
    """Disposition en flux (.chips { flex-wrap: wrap; gap: 6px })."""

    def __init__(self, parent: QWidget | None = None, gap: int = 6) -> None:
        super().__init__(parent)
        self._items: list[QLayoutItem] = []
        self.gap = gap
        self.setContentsMargins(0, 0, 0, 0)

    def addItem(self, item: QLayoutItem) -> None:
        self._items.append(item)

    def insertWidget(self, i: int, w: QWidget) -> None:
        self.addChildWidget(w)
        self._items.insert(i, QWidgetItem(w))
        self.invalidate()

    def count(self) -> int:
        return len(self._items)

    def itemAt(self, i: int) -> QLayoutItem | None:
        return self._items[i] if 0 <= i < len(self._items) else None

    def takeAt(self, i: int) -> QLayoutItem | None:
        return self._items.pop(i) if 0 <= i < len(self._items) else None

    def expandingDirections(self) -> Qt.Orientation:
        return Qt.Orientation(0)

    def hasHeightForWidth(self) -> bool:
        return True

    def heightForWidth(self, w: int) -> int:
        return self._do(QRect(0, 0, w, 0), apply=False)

    def setGeometry(self, rect: QRect) -> None:
        super().setGeometry(rect)
        self._do(rect, apply=True)

    def sizeHint(self) -> QSize:
        return self.minimumSize()

    def minimumSize(self) -> QSize:
        s = QSize()
        for it in self._items:
            s = s.expandedTo(it.minimumSize())
        return s

    def _do(self, rect: QRect, apply: bool) -> int:
        x, y, line = rect.x(), rect.y(), 0
        for it in self._items:
            hint = it.sizeHint()
            if x + hint.width() > rect.right() + 1 and line > 0:
                x, y, line = rect.x(), y + line + self.gap, 0
            if apply:
                it.setGeometry(QRect(QPoint(x, y), hint))
            x += hint.width() + self.gap
            line = max(line, hint.height())
        return y + line - rect.y()


STATUS_COLORS = {
    "normal": ("rgba(46,229,157,0.14)", style.GREEN, ""),
    "unusual": ("rgba(255,179,71,0.14)", style.ORANGE, ""),
    "abnormal": ("rgba(255,92,108,0.14)", style.RED, ""),
    "blocked": ("rgba(255,92,108,0.22)", "#ff8a96", "rgba(255,92,108,0.35)"),
    "server": ("rgba(61,214,255,0.14)", style.CYAN, ""),
}
BADGE_COLORS = {
    "VPN": ((168, 85, 247), "#d4a8ff"),
    "AMI": ((46, 229, 157), style.GREEN),
    "NOUVEAU": ((61, 214, 255), style.CYAN),
    "RÉCIDIVISTE": ((255, 92, 108), "#ff8a96"),
}


def qcolor(css: str) -> QColor:
    if css.startswith("rgba("):
        r, g, b, a = (float(x) for x in css[5:-1].split(","))
        return QColor(int(r), int(g), int(b), int(a * 255))
    return QColor(css)


def draw_pill(
    p: QPainter,
    x: float,
    cy: float,
    text: str,
    bg: QColor,
    fg: QColor,
    border: QColor | None = None,
    px: float = 10,
    pad: tuple[float, float] = (8, 3),
    radius: float = 6,
) -> float:
    """Dessine une pastille ; renvoie sa largeur."""
    f = font(px, 700)
    p.setFont(f)
    fm = QFontMetrics(f)
    w = fm.horizontalAdvance(text) + 2 * pad[0]
    h = fm.height() + 2 * pad[1] - 2
    r = QRectF(x, cy - h / 2, w, h)
    p.setPen(QPen(border, 1) if border is not None else Qt.PenStyle.NoPen)
    p.setBrush(bg)
    p.drawRoundedRect(r.adjusted(0.5, 0.5, -0.5, -0.5), radius, radius)
    p.setPen(fg)
    p.drawText(r, Qt.AlignmentFlag.AlignCenter, text)
    return w


class PlayersDelegate(QStyledItemDelegate):
    """Peint chaque cellule comme la maquette (td 7/10 px, pastilles, mini-barres)."""

    def __init__(self, page: Any) -> None:
        super().__init__(page.table)
        self.page = page

    def paint(
        self,
        p: QPainter,
        opt: QStyleOptionViewItem,
        index: QModelIndex | QPersistentModelIndex,
    ) -> None:
        rows = self.page.view_rows
        if index.row() >= len(rows):
            return
        r = rows[index.row()]
        rect = QRect(opt.rect)
        state = opt.state
        p.save()
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        if r.blocked:
            p.fillRect(rect, QColor(255, 92, 108, 20))
        elif state & QStyle.StateFlag.State_Selected:
            p.fillRect(rect, QColor(61, 214, 255, 26))
        elif state & QStyle.StateFlag.State_MouseOver:
            p.fillRect(rect, QColor(61, 214, 255, 10))
        p.setPen(QColor(120, 170, 255, 15))
        p.drawLine(rect.left(), rect.bottom(), rect.right(), rect.bottom())
        text = QColor("#ffc0c6") if r.blocked else QColor(style.TEXT)
        x = rect.left() + 10.0
        cy = rect.center().y() + 0.5
        col = index.column()
        if col == 0:
            flag_icon(r.country).paint(p, QRect(int(x), int(cy - 7), 20, 14))
            f = font(12, 400)
            p.setFont(f)
            p.setPen(text)
            avail = rect.right() - 10 - (x + 28)
            name = QFontMetrics(f).elidedText(
                index.data() or "", Qt.TextElideMode.ElideRight, int(avail)
            )
            p.drawText(
                QRectF(x + 28, rect.top(), avail, rect.height()),
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                name,
            )
        elif col == 1:
            f = font(11.5, 400, mono=True)
            p.setFont(f)
            p.setPen(text if r.blocked else QColor("#b8c4d8"))
            fm = QFontMetrics(f)
            p.drawText(
                QRectF(x, rect.top(), fm.horizontalAdvance(r.ip) + 2, rect.height()),
                Qt.AlignmentFlag.AlignVCenter,
                r.ip,
            )
            x += fm.horizontalAdvance(r.ip) + 6
            for tag in self.page.tags(r):
                rgb, fg = BADGE_COLORS.get(tag, ((255, 179, 71), style.ORANGE))
                bg = QColor(*rgb, 46)
                border = QColor(*rgb, 115)
                label_ = ("🔒 " if tag == "VPN" else "") + tag
                need = QFontMetrics(font(9, 700)).horizontalAdvance(label_) + 10
                if x + need > rect.right() - 4:
                    break
                x += (
                    draw_pill(p, x, cy, label_, bg, QColor(fg), border, 9, (5, 1), 8)
                    + 4
                )
            if r.pseudo and x < rect.right() - 30:
                f = font(11)
                p.setFont(f)
                p.setPen(QColor(style.MUTED))
                pseudo = QFontMetrics(f).elidedText(
                    r.pseudo, Qt.TextElideMode.ElideRight, int(rect.right() - x - 6)
                )
                p.drawText(
                    QRectF(x + 2, rect.top(), rect.right() - x, rect.height()),
                    Qt.AlignmentFlag.AlignVCenter,
                    pseudo,
                )
        elif col == 2:
            p.setFont(font(12))
            p.setPen(text if r.blocked else QColor(style.MUTED))
            p.drawText(
                rect.adjusted(10, 0, -4, 0),
                Qt.AlignmentFlag.AlignVCenter,
                index.data() or "",
            )
        elif col == 3:
            f = font(12)
            p.setFont(f)
            hot = r.blocked or r.level >= 2
            warn = r.level == 1
            p.setPen(QColor(style.RED) if hot else text)
            p.drawText(
                QRectF(x, rect.top(), 36, rect.height()),
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
                index.data() or "",
            )
            hist: deque[float] = self.page.history.get(r.ip, deque())
            vals = list(hist)[-9:]
            top = max(vals) if vals and max(vals) > 0 else 1.0
            bar = QColor(style.RED if hot else style.ORANGE if warn else style.CYAN)
            bar.setAlphaF(0.7)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(bar)
            bx = x + 36 + 8
            for v in vals:
                h = max(2.0, 14 * v / top)
                p.drawRoundedRect(QRectF(bx, cy + 7 - h, 3, h), 1, 1)
                bx += 4.5
        elif col == 4:
            kind = self.page.status_kind(r)
            sbg, fg, sborder = STATUS_COLORS[kind]
            shown = str(index.data() or "")
            shown = (
                shown.capitalize() if shown.isupper() else shown[:1].upper() + shown[1:]
            )
            draw_pill(
                p,
                x,
                cy,
                shown,
                qcolor(sbg),
                QColor(fg),
                qcolor(sborder) if sborder else None,
            )
        p.restore()

    def sizeHint(
        self, opt: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex
    ) -> QSize:
        return QSize(80, ROW_H)


class AlertDelegate(QStyledItemDelegate):
    """.alert-item : heure (54 px) · point coloré · texte 11 px (gras avant « : »)."""

    PAD_X, PAD_Y, TIME_W = 6, 9, 54

    def __init__(self, view: QListWidget) -> None:
        super().__init__(view)
        self.view = view

    def _doc(self, html: str, width: float) -> QTextDocument:
        doc = QTextDocument()
        doc.setDefaultFont(font(11))
        doc.setDocumentMargin(0)
        doc.setDefaultStyleSheet(
            f"body {{ color: #c5d0e0; }} b {{ color: {style.TEXT}; }}"
        )
        doc.setHtml(f"<body>{html}</body>")
        cur = QTextCursor(doc)
        cur.select(QTextCursor.SelectionType.Document)
        fmt = QTextBlockFormat()
        fmt.setLineHeight(15.4, QTextBlockFormat.LineHeightTypes.FixedHeight.value)
        cur.mergeBlockFormat(fmt)  # line-height: 1.4 × 11 px
        doc.setTextWidth(width)
        return doc

    def _text_w(self) -> float:
        return float(self.view.viewport().width() - 2 * self.PAD_X - self.TIME_W - 28)

    def paint(
        self,
        p: QPainter,
        opt: QStyleOptionViewItem,
        index: QModelIndex | QPersistentModelIndex,
    ) -> None:
        data = index.data(Qt.ItemDataRole.UserRole)
        if not isinstance(data, tuple):
            return
        when, color, html = data
        rect = QRect(opt.rect)
        p.save()
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        if index.row() < self.view.count() - 1:
            p.setPen(QColor(120, 170, 255, 15))
            p.drawLine(rect.left(), rect.bottom(), rect.right(), rect.bottom())
        x = rect.left() + self.PAD_X
        y = rect.top() + self.PAD_Y
        p.setFont(font(10))
        p.setPen(QColor(style.DIM))
        p.drawText(QRectF(x, y + 1, self.TIME_W, 14), Qt.AlignmentFlag.AlignLeft, when)
        x += self.TIME_W + 10
        c = QColor(color)
        glow = QColor(c)
        glow.setAlpha(60)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(glow)
        p.drawEllipse(QRectF(x - 2, y + 2, 12, 12))
        p.setBrush(c)
        p.drawEllipse(QRectF(x, y + 4, 8, 8))
        x += 18
        doc = self._doc(html, self._text_w())
        p.translate(x, y)
        doc.drawContents(p)
        p.restore()

    def sizeHint(
        self, opt: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex
    ) -> QSize:
        data = index.data(Qt.ItemDataRole.UserRole)
        if not isinstance(data, tuple):
            return QSize(10, 10)
        h = self._doc(data[2], self._text_w()).size().height()
        return QSize(int(self._text_w()), int(h) + 2 * self.PAD_Y)


class Sparkline(QWidget):
    """Courbe « trafic entrant 60 s » avec aire dégradée (.chart-box)."""

    def __init__(self, maxlen: int) -> None:
        super().__init__()
        self.maxlen = maxlen
        self.values: deque[float] = deque(maxlen=maxlen)
        self.setFixedHeight(48)

    def push(self, v: float) -> None:
        self.values.append(v)
        self.update()

    def paintEvent(self, _e: QPaintEvent) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        vals = list(self.values)
        if len(vals) >= 2:
            top = (max(vals) or 1.0) * 1.15
            w, h = float(self.width()), float(self.height() - 2)
            step = w / (self.maxlen - 1)
            x0 = w - step * (len(vals) - 1)
            pts = [
                QPointF(x0 + i * step, 1 + h - h * v / top) for i, v in enumerate(vals)
            ]
            path = QPainterPath(QPointF(pts[0].x(), h + 1))
            for pt in pts:
                path.lineTo(pt)
            path.lineTo(QPointF(pts[-1].x(), h + 1))
            g = QLinearGradient(0, 0, 0, h)
            g.setColorAt(0, QColor(61, 214, 255, 90))
            g.setColorAt(1, QColor(61, 214, 255, 0))
            p.fillPath(path, QBrush(g))
            p.setPen(QPen(QColor(style.CYAN), 1.6))
            p.drawPolyline(pts)
            peak = max(range(len(vals)), key=lambda i: vals[i])
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(style.RED))
            p.drawEllipse(pts[peak], 2.5, 2.5)
        p.end()


class SwitchRow(QWidget):
    """.toggle-row : libellé + sous-titre à gauche, (pastille) + interrupteur à droite."""

    def __init__(
        self,
        title: str,
        sub: str,
        on_click: Callable[[], None] | None = None,
        badge: bool = False,
        switch: Switch | None = None,
    ) -> None:
        super().__init__()
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 6, 0, 6)
        lay.setSpacing(8)
        txt = QVBoxLayout()
        txt.setSpacing(2)
        t, sb = label(title, "fieldLabel"), label(sub, "rowSub")
        t.setFixedHeight(15)
        sb.setFixedHeight(13)
        txt.addWidget(t)
        txt.addWidget(sb)
        lay.addLayout(txt, 1)
        self.pill: QLabel | None = None
        if badge:
            self.pill = QLabel()
            lay.addWidget(self.pill, 0, Qt.AlignmentFlag.AlignVCenter)
        self.switch = switch or Switch()
        if on_click is not None:
            self.switch.clicked.connect(lambda _c=False: on_click())
        lay.addWidget(self.switch, 0, Qt.AlignmentFlag.AlignVCenter)
        self.switch.toggled.connect(lambda _v: self.refresh_pill())
        self.refresh_pill()

    def refresh_pill(self) -> None:
        if self.pill is not None:
            on = self.switch.isChecked()
            set_pill(self.pill, "ACTIVÉ" if on else "DÉSACTIVÉ", "on" if on else "off")

    def set_state(self, on: bool) -> None:
        self.switch.blockSignals(True)
        self.switch.setChecked(on)
        self.switch.blockSignals(False)
        self.refresh_pill()
        self.switch.update()
