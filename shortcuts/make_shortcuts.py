#!/usr/bin/env python3
"""Собирает файлы Команд (.shortcut) для iPhone и подписывает их утилитой `shortcuts` на Mac.

Запуск из корня проекта: python3 shortcuts/make_shortcuts.py
Результат: shortcuts/*.shortcut (подписанные, импортируются на iPhone по нажатию).

Устройство: одна Команда на режим с единственным действием a-Shell «Выполнить команду»
(в приложении) и общая Команда «DPI Save», которую a-Shell вызывает в конце через
`open shortcuts://run-shortcut?name=DPI%20Save`. Так сделано потому, что при запуске
«в приложении» действие Shortcuts завершается сразу, не дожидаясь команды, а файлы
для Команды a-Shell отдаёт только из своей общей папки $SHORTCUTS.
"""

from __future__ import annotations

import plistlib
import subprocess
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from dpiphone.modes import MODE_TESTS  # noqa: E402

EXECUTE = "AsheKube.app.a-Shell.ExecuteCommandIntent"
GET_FILE = "AsheKube.app.a-Shell.GetFileIntent"
SHOW_RESULT = "is.workflow.actions.showresult"
SAVE_FILE = "is.workflow.actions.documentpicker.save"

SAVE_SHORTCUT_NAME = "DPI Save"
ICLOUD_DIR = "DPI Logs"
FILES = ("summary.txt", "name.txt", "last.log", "last.json")

RUN_SHORTCUTS = {
    "quick": "Сеть быстро",
    "full": "Сеть полностью",
    "sni": "Сеть белые SNI",
}


def command_text(mode: str) -> str:
    shared = " ".join("$SHORTCUTS/dpiphone/" + f for f in FILES)
    local = " ".join("out/" + f for f in FILES)
    return "\n".join([
        "cd $HOME/Documents/dpiphone",
        "mkdir -p $SHORTCUTS/dpiphone",
        "rm -f {} {}".format(local, shared),
        "export COLUMNS=120",
        "python ../dpi-detector/dpi_detector.py -t {} --batch -c 20 -o out/raw.log > out/console.log 2>&1".format(MODE_TESTS[mode]),
        "python report.py --mode {}".format(mode),
        "cp {} $SHORTCUTS/dpiphone/".format(local),
        "open shortcuts://run-shortcut?name=DPI%20Save",
    ])


def _uuid() -> str:
    return str(uuid.uuid4()).upper()


def _output_ref(output_uuid: str, as_text: bool = False) -> dict:
    ref = {"Type": "ActionOutput", "OutputName": "File", "OutputUUID": output_uuid}
    if as_text:
        ref["Aggrandizements"] = [{"Type": "WFCoercionVariableAggrandizement",
                                   "CoercionItemClass": "WFStringContentItem"}]
    return ref


def _attachment(output_uuid: str, as_text: bool = False) -> dict:
    return {"Value": _output_ref(output_uuid, as_text), "WFSerializationType": "WFTextTokenAttachment"}


def _token_string(prefix: str, output_uuid: str, suffix: str) -> dict:
    """Текст с одной подстановкой: prefix + <результат действия как текст> + suffix."""
    return {
        "Value": {
            "string": prefix + "￼" + suffix,
            "attachmentsByRange": {"{%d, 1}" % len(prefix): _output_ref(output_uuid, as_text=True)},
        },
        "WFSerializationType": "WFTextTokenString",
    }


def action(identifier: str, params: dict) -> dict:
    return {"WFWorkflowActionIdentifier": identifier, "WFWorkflowActionParameters": params}


def workflow(actions: list, glyph: int, color: int) -> dict:
    return {
        "WFWorkflowActions": actions,
        "WFWorkflowClientVersion": "3612.0.1.2",
        "WFWorkflowHasOutputFallback": False,
        "WFWorkflowHasShortcutInputVariables": False,
        "WFWorkflowIcon": {"WFWorkflowIconGlyphNumber": glyph, "WFWorkflowIconStartColor": color},
        "WFWorkflowImportQuestions": [],
        "WFWorkflowInputContentItemClasses": [],
        "WFWorkflowMinimumClientVersion": 900,
        "WFWorkflowMinimumClientVersionString": "900",
        "WFWorkflowOutputContentItemClasses": [],
        "WFWorkflowTypes": [],
        "WFQuickActionSurfaces": [],
    }


def run_shortcut(mode: str) -> dict:
    cmd = action(EXECUTE, {
        "UUID": _uuid(),
        "ShowWhenRun": False,
        "Show-command": True,
        "command": command_text(mode),
        "openWindow": "open",     # всегда открывать приложение: python в расширении не работает
        "keepGoing": True,
    })
    colors = {"quick": 4282601983, "full": 431817727, "sni": 3980825855}
    return workflow([cmd], glyph=59771, color=colors[mode])


def save_shortcut() -> dict:
    s, n, l, j = _uuid(), _uuid(), _uuid(), _uuid()

    def get_file(name: str, out_uuid: str) -> dict:
        # copyFile: отдать содержимое, а не ссылку на файл в песочнице a-Shell; без него
        # Команды на iOS 18 получают «Нет объектов» (см. GetFileIntentHandler.swift в a-Shell)
        return action(GET_FILE, {"UUID": out_uuid, "ShowWhenRun": False, "copyFile": True,
                                 "fileName": "dpiphone/" + name, "errorIfNotFound": True})

    def save(src_uuid: str, ext: str) -> dict:
        return action(SAVE_FILE, {
            "UUID": _uuid(),
            "WFInput": _attachment(src_uuid),
            "WFAskWhereToSave": False,
            "WFSaveFileOverwrite": True,
            "WFFileStorageService": "iCloud Drive",
            "WFFileDestinationPath": _token_string(ICLOUD_DIR + "/", n, ext),
        })

    actions = [
        get_file("summary.txt", s),
        action(SHOW_RESULT, {"UUID": _uuid(), "Text": _token_string("", s, "")}),
        get_file("name.txt", n),
        get_file("last.log", l),
        save(l, ".log"),
        get_file("last.json", j),
        save(j, ".json"),
    ]
    return workflow(actions, glyph=59511, color=2071128575)


def write_and_sign(name: str, wf: dict) -> Path:
    unsigned = HERE / "unsigned" / (name + ".shortcut")
    unsigned.parent.mkdir(exist_ok=True)
    with open(unsigned, "wb") as f:
        plistlib.dump(wf, f, fmt=plistlib.FMT_XML, sort_keys=True)
    signed = HERE / (name + ".shortcut")
    subprocess.run(["shortcuts", "sign", "--mode", "anyone", "--input", str(unsigned), "--output", str(signed)],
                   check=True)
    return signed


def main() -> None:
    for mode, name in RUN_SHORTCUTS.items():
        print(write_and_sign(name, run_shortcut(mode)))
    print(write_and_sign(SAVE_SHORTCUT_NAME, save_shortcut()))


if __name__ == "__main__":
    main()
