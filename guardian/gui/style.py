"""Feuille de style (thème sombre des maquettes approuvées)."""

BG = "#0a0d14"
PANEL = "#141a28"
BORDER = "#1f2a3d"
TEXT = "#e8eef8"
MUTED = "#8b97ad"
CYAN = "#3dd6ff"
GREEN = "#2ee59d"
RED = "#ff5c6c"
ORANGE = "#ffb347"
VIOLET = "#a68bff"

QSS = f"""
QWidget {{ background: {BG}; color: {TEXT}; font-family: 'Segoe UI', 'DejaVu Sans';
  font-size: 12px; }}
#sidebar {{ background: #0a0e16; border-right: 1px solid {BORDER}; }}
#brand {{ font-size: 15px; font-weight: 700; }}
#brandSub {{ color: {MUTED}; font-size: 9px; }}
QPushButton#nav {{ text-align: left; padding: 9px 12px; border-radius: 8px;
  color: {MUTED}; background: transparent; border: 1px solid transparent; }}
QPushButton#nav:checked {{ color: {TEXT}; background: #10263a;
  border: 1px solid #1d4a63; }}
#card {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 10px; }}
#card QLabel, #card QCheckBox {{ background: transparent; }}
#cardTitle {{ font-weight: 600; }}
#cardSub {{ color: {MUTED}; font-size: 10px; }}
#big {{ font-size: 20px; font-weight: 700; }}
#bigRed {{ font-size: 20px; font-weight: 700; color: {RED}; }}
#pillOn {{ color: {GREEN}; background: rgba(46,229,157,0.14); border-radius: 4px;
  padding: 2px 6px; font-size: 10px; font-weight: 700; }}
#pillOff {{ color: {RED}; background: rgba(255,92,108,0.14); border-radius: 4px;
  padding: 2px 6px; font-size: 10px; font-weight: 700; }}
#pillInfo {{ color: {CYAN}; background: rgba(61,214,255,0.14); border-radius: 4px;
  padding: 2px 6px; font-size: 10px; font-weight: 700; }}
QCheckBox#switch::indicator {{ width: 34px; height: 18px; border-radius: 9px;
  background: #3a2230; border: 1px solid {RED}; }}
QCheckBox#switch::indicator:checked {{ background: {GREEN}; border: 1px solid {GREEN}; }}
QTableWidget {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 10px;
  gridline-color: {BORDER}; selection-background-color: #1b3550; }}
QHeaderView::section {{ background: {PANEL}; color: {MUTED}; border: none;
  border-bottom: 1px solid {BORDER}; padding: 6px; font-size: 10px; }}
QListWidget {{ background: {PANEL}; border: 1px solid {BORDER}; border-radius: 10px; }}
QPushButton {{ background: #1a2335; border: 1px solid {BORDER}; border-radius: 6px;
  padding: 6px 10px; }}
QPushButton:hover {{ border-color: {CYAN}; }}
QPushButton#danger {{ color: {RED}; border-color: #6b2a35; background: #2a1520; }}
QPushButton#ok {{ color: {GREEN}; border-color: #1f5f48; background: #10261f; }}
QPushButton#seg {{ background: transparent; }}
QPushButton#seg:checked {{ background: #10263a; color: {CYAN}; border-color: #1d4a63; }}
QLineEdit, QSpinBox, QDoubleSpinBox {{ background: #0e1420; border: 1px solid {BORDER};
  border-radius: 6px; padding: 4px; }}
QSlider::groove:horizontal {{ height: 4px; background: #24304a; border-radius: 2px; }}
QSlider::sub-page:horizontal {{ background: {CYAN}; border-radius: 2px; }}
QSlider::handle:horizontal {{ background: white; width: 14px; margin: -6px 0;
  border-radius: 7px; }}
QPushButton#chip {{ color: #ffb3bb; background: rgba(255,92,108,0.12);
  border: 1px solid #6b2a35; border-radius: 6px; padding: 3px 8px; }}
QPushButton#chipAdd {{ color: {CYAN}; background: rgba(61,214,255,0.10);
  border: 1px solid #1d4a63; border-radius: 6px; padding: 3px 10px; }}
#statusOk {{ color: {GREEN}; font-weight: 600; }}
#statusBad {{ color: {RED}; font-weight: 600; }}
#footer {{ color: {MUTED}; font-size: 10px; }}
#footerOk {{ color: {GREEN}; font-size: 10px; }}
"""
