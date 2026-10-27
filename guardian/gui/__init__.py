"""Lot 5 — interface graphique PySide6 (remplace la console ; ``--console`` la garde).

La GUI ne touche JAMAIS la boucle de capture WinDivert : elle lit un instantané
de la session en fond (sous son verrou, brièvement) via un QTimer, et ses actions
appellent exactement les mêmes fonctions que les touches de la console
(``menu.livesession.handle_key``).
"""
