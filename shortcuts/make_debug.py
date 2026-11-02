#!/usr/bin/env python3
"""Отладочная Команда «DPI Debug»: окно на каждом шаге, чтобы увидеть, где обрывается DPI Save."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from make_shortcuts import GET_FILE, _attachment, _uuid, action, workflow, write_and_sign

ALERT = "is.workflow.actions.alert"
PREVIEW = "is.workflow.actions.previewdocument"


def alert(text: str) -> dict:
    return action(ALERT, {"UUID": _uuid(), "WFAlertActionTitle": "DPI Debug",
                          "WFAlertActionMessage": text, "WFAlertActionCancelButtonShown": False})


s = _uuid()
actions = [
    alert("1. Команда запустилась"),
    action(GET_FILE, {"UUID": s, "ShowWhenRun": False, "copyFile": True, "fileName": "dpiphone/summary.txt", "errorIfNotFound": True}),
    alert("2. Получить файл отработал"),
    action(PREVIEW, {"UUID": _uuid(), "WFInput": _attachment(s)}),
    alert("3. Quick Look отработал"),
]
print(write_and_sign("DPI Debug", workflow(actions, glyph=59511, color=4292093695)))
