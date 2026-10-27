"""Feuille de style : valeurs reprises du CSS de la maquette (guardian-ui-mockup)."""

BG = "#0a0d14"
PANEL = "rgba(22, 28, 42, 0.72)"
PANEL_SOLID = "#141a28"
BORDER = "rgba(120, 170, 255, 0.14)"
ROW_LINE = "rgba(120, 170, 255, 0.06)"
TEXT = "#e8eef8"
MUTED = "#8b97ad"
DIM = "#5c6a82"
CYAN = "#3dd6ff"
BLUE = "#4b7cff"
GREEN = "#2ee59d"
RED = "#ff5c6c"
ORANGE = "#ffb347"
VIOLET = "#a855f7"
FONT = "'Segoe UI', 'Selawik', 'Inter', 'DejaVu Sans'"
MONO = "'Consolas', 'Cascadia Mono', 'DejaVu Sans Mono'"
ACTIVE_GRAD = (
    "qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 rgba(61,214,255,0.14), "
    "stop:1 rgba(75,124,255,0.08))"
)

QSS = f"""
QWidget {{ background: transparent; color: {TEXT}; font-family: {FONT};
  font-size: 12px; }}
QMainWindow, #root {{ background: qlineargradient(x1:0, y1:0, x2:0.55, y2:1,
  stop:0 #0c111c, stop:0.5 #0a0d14, stop:1 #0b1018); }}
QToolTip {{ background: #1a2233; color: {TEXT}; border: 1px solid {BORDER};
  padding: 4px 6px; }}
QMenu, QInputDialog, QDialog {{ background: {PANEL_SOLID}; }}

/* Barre latérale (.sidebar, .brand, .nav-item) */
#sidebar {{ background: rgba(10, 14, 22, 0.85); border-right: 1px solid {BORDER}; }}
#brandMark {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
  stop:0 rgba(61,214,255,0.25), stop:1 rgba(75,124,255,0.2));
  border: 1px solid rgba(61,214,255,0.35); border-radius: 9px; }}
#brand {{ font-size: 15px; font-weight: 700; }}
#brandSub {{ color: {DIM}; font-size: 10px; }}
QPushButton#nav {{ text-align: left; padding: 0; border-radius: 9px;
  background: transparent; border: 1px solid transparent; }}
QPushButton#nav:hover {{ background: rgba(255,255,255,0.025); }}
QPushButton#nav:checked {{ background: {ACTIVE_GRAD};
  border: 1px solid rgba(61,214,255,0.22); }}
#navText {{ color: {MUTED}; font-size: 13px; font-weight: 400; }}
#navText[active="true"] {{ color: {TEXT}; }}
#navIco {{ color: {MUTED}; font-size: 14px; }}
#navIco[active="true"] {{ color: {CYAN}; }}
#sideFoot {{ border-top: 1px solid {BORDER}; }}
#langSwitch {{ background: rgba(255,255,255,0.04); border: 1px solid {BORDER};
  border-radius: 8px; }}
QPushButton#langBtn {{ padding: 6px 0; font-size: 11px; font-weight: 600; color: {DIM};
  border-radius: 6px; border: none; background: transparent; }}
QPushButton#langBtn:checked {{ background: rgba(61,214,255,0.16); color: {CYAN}; }}
#driver {{ background: rgba(46,229,157,0.08); border: 1px solid rgba(46,229,157,0.22);
  border-radius: 8px; }}
#driver[bad="true"] {{ background: rgba(255,92,108,0.08);
  border: 1px solid rgba(255,92,108,0.22); }}
#driverText {{ color: {GREEN}; font-size: 11px; }}
#driverText[bad="true"] {{ color: {RED}; }}
#panicBox {{ background: rgba(255,92,108,0.06); border: 1px solid rgba(255,92,108,0.2);
  border-radius: 8px; }}

/* Cartes (.toggle-card, .stat-card, .panel, .set-card) */
#card, #panel {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 12px; }}
#panelH {{ border-bottom: 1px solid {BORDER}; }}
#panelTitle {{ font-size: 13px; font-weight: 650; }}
#meta {{ color: {DIM}; font-size: 11px; }}
#cardTitle {{ font-size: 12px; font-weight: 600; }}
#cardSub {{ color: {DIM}; font-size: 10px; }}
#statVal {{ font-size: 20px; font-weight: 700; }}
#statVal[red="true"] {{ color: {RED}; }}
#statLbl {{ color: {MUTED}; font-size: 11px; }}
#statIco {{ background: rgba(61,214,255,0.1); border: 1px solid rgba(61,214,255,0.2);
  border-radius: 10px; color: {CYAN}; font-size: 16px; }}
#statIco[red="true"] {{ background: rgba(255,92,108,0.1);
  border: 1px solid rgba(255,92,108,0.25); color: {RED}; }}
#pillOn, #pillOff, #pillInfo {{ font-size: 10px; font-weight: 700; padding: 3px 8px;
  border-radius: 6px; }}
#pillOn {{ color: {GREEN}; background: rgba(46,229,157,0.14); }}
#pillOff {{ color: {RED}; background: rgba(255,92,108,0.14); }}
#pillInfo {{ color: {CYAN}; background: rgba(61,214,255,0.18); }}
#tag {{ font-size: 9px; font-weight: 600; padding: 2px 6px; border-radius: 4px;
  background: rgba(140,150,170,0.15); color: #9aa6bc; }}
#sectionH {{ color: {DIM}; font-size: 10px; font-weight: 650; }}
#legend {{ background: rgba(0,0,0,0.12); border-top: 1px solid {ROW_LINE}; }}
#legendText {{ color: {DIM}; font-size: 10px; }}
#vpnBadge {{ font-size: 9px; font-weight: 700; padding: 1px 6px 1px 4px;
  border-radius: 8px; background: rgba(168,85,247,0.18);
  border: 1px solid rgba(168,85,247,0.45); color: #d4a8ff; }}
#rockstar, #chartBox {{ background: rgba(0,0,0,0.15); border-top: 1px solid {BORDER};
  border-bottom-left-radius: 12px; border-bottom-right-radius: 12px; }}
#chartVal {{ color: {CYAN}; font-size: 10px; font-weight: 600; }}

/* Tableau (thead th / tbody td) */
QTableWidget#players, QTableWidget#servers, QTableWidget#plain, QListWidget {{
  background: transparent; border: none; outline: 0; }}
QTableWidget#plain::item {{ padding: 0 10px; border-bottom: 1px solid {ROW_LINE}; }}
QTableWidget#plain::item:selected, QListWidget::item:selected {{
  background: rgba(61,214,255,0.10); color: {TEXT}; }}
QListWidget#friendsList::item {{ padding: 8px 10px; border-bottom: 1px solid {ROW_LINE}; }}
QHeaderView {{ background: transparent; }}
QHeaderView::section {{ background: rgba(0,0,0,0.2); color: {DIM}; border: none;
  border-bottom: 1px solid {BORDER}; padding: 0 10px; font-size: 10px; font-weight: 600; }}
QScrollBar:vertical {{ width: 8px; background: transparent; }}
QScrollBar::handle:vertical {{ background: rgba(120,170,255,0.18); border-radius: 4px;
  min-height: 20px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}

/* Boutons (.btn-act, chips, segmented) */
QPushButton {{ background: rgba(255,255,255,0.04); border: 1px solid {BORDER};
  border-radius: 6px; padding: 4px 10px; font-size: 11px; font-weight: 600;
  color: #c0cad8; }}
QPushButton:hover {{ border-color: rgba(61,214,255,0.45); color: {TEXT}; }}
QPushButton#danger {{ color: {RED}; border: 1px solid rgba(255,92,108,0.4);
  background: rgba(255,92,108,0.12); }}
QPushButton#danger:hover {{ background: rgba(255,92,108,0.2); }}
QPushButton#ok {{ color: {GREEN}; border: 1px solid rgba(46,229,157,0.4);
  background: rgba(46,229,157,0.12); }}
QPushButton#ok:hover {{ background: rgba(46,229,157,0.2); }}
QPushButton#ghost {{ padding: 3px 10px; color: {MUTED}; }}
#segmented {{ background: rgba(0,0,0,0.25); border: 1px solid {BORDER};
  border-radius: 8px; }}
QPushButton#seg {{ background: transparent; border: none; border-radius: 6px;
  padding: 7px 0; font-size: 12px; font-weight: 600; color: {DIM}; }}
QPushButton#seg:checked {{ background: rgba(61,214,255,0.18); color: {CYAN}; }}
QPushButton#chip {{ color: #ff9aa4; background: rgba(255,92,108,0.12);
  border: 1px solid rgba(255,92,108,0.3); border-radius: 13px; padding: 5px 10px;
  font-size: 11px; font-weight: 600; }}
QPushButton#chipAdd {{ color: {CYAN}; background: rgba(61,214,255,0.08);
  border: 1px solid rgba(61,214,255,0.25); border-radius: 13px; padding: 5px 10px;
  font-size: 11px; font-weight: 600; }}
QLineEdit {{ background: rgba(0,0,0,0.25); border: 1px solid {BORDER};
  border-radius: 6px; padding: 4px 8px; font-size: 11px; }}
QLineEdit:focus {{ border-color: rgba(61,214,255,0.45); }}

/* Réglages */
#h1 {{ font-size: 16px; font-weight: 700; }}
#hint {{ color: {DIM}; font-size: 11px; }}
#h3 {{ font-size: 12.5px; font-weight: 650; }}
#h3Ico {{ color: {CYAN}; font-size: 14px; }}
#setDesc {{ color: {MUTED}; font-size: 10.5px; }}
#fieldLabel {{ color: #c0cad8; font-size: 12px; }}
#fieldVal {{ color: {CYAN}; font-size: 12px; font-weight: 650; }}
#rowSub {{ color: {DIM}; font-size: 10px; }}
QSlider {{ min-height: 16px; }}
QSlider::groove:horizontal {{ height: 6px; background: rgba(255,255,255,0.08);
  border: 1px solid rgba(120,170,255,0.12); border-radius: 3px; }}
QSlider::sub-page:horizontal {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
  stop:0 {BLUE}, stop:1 {CYAN}); border-radius: 3px; }}
QSlider::handle:horizontal {{ background: white; width: 10px; height: 10px;
  margin: -4px 0; border: 2px solid rgba(61,214,255,0.45); border-radius: 7px; }}

/* Pied (.footer) */
#footer {{ color: {DIM}; font-size: 11px; }}
#kbd {{ padding: 1px 6px; border-radius: 4px; background: rgba(255,255,255,0.06);
  border: 1px solid rgba(255,255,255,0.1); font-size: 10px; color: {MUTED}; }}
#footerOk {{ color: {GREEN}; font-size: 11px; }}
#statusOk {{ color: {GREEN}; font-size: 11px; font-weight: 600; }}
#statusBad {{ color: {RED}; font-size: 11px; font-weight: 600; }}
"""
