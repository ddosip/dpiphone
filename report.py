#!/usr/bin/env python3
"""Разбирает лог движка, считает вердикт, пишет короткий отчёт и файлы для Команды.

python report.py --mode quick|full|sni --net "<имя сети>" [--out out] [--history history] [--engine ../dpi-detector]
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from dpiphone import __version__, history
from dpiphone.compare import compare
from dpiphone.model import RunRecord, RunResult, Verdict
from dpiphone.modes import MODE_TESTS
from dpiphone.netname import file_stem, sanitize
from dpiphone.parse import load_known_domains, parse_log
from dpiphone.summary import render
from dpiphone.verdict import TEXT, decide

HERE = Path(__file__).resolve().parent
NO_OUTPUT = "нет вывода движка"


def _engine_commit() -> str:
    try:
        return (HERE / "engine.lock").read_text(encoding="utf-8").strip()[:12]
    except OSError:
        return "unknown"


def _read_engine_log(out: Path):
    """(текст лога, неполный ли он): raw.log из -o, иначе console.log, иначе заглушка.

    Прочитанные файлы переименовываются в *.prev: движок пишет raw.log только в конце,
    и без этого упавший прогон подхватил бы raw.log прошлого.
    """
    raw, console = out / "raw.log", out / "console.log"
    text, partial = NO_OUTPUT, True
    if raw.exists():
        text, partial = raw.read_text(encoding="utf-8", errors="replace"), False
    elif console.exists():
        text, partial = console.read_text(encoding="utf-8", errors="replace"), True
    for p in (raw, console):
        if p.exists():
            p.replace(p.with_suffix(".prev.log"))
    return text, partial


def build_record(text: str, mode: str, net_raw: str, hist: Path, engine: Path, now: datetime) -> RunRecord:
    run = parse_log(text, load_known_domains(engine))
    net = sanitize(net_raw)
    base = history.find_base(hist, net) if mode != "sni" else None
    latest = history.find_latest(hist, net) if mode != "sni" else None
    # ASN подтверждён, если предыдущий прогон на этой сети (любой годности) видел тот же ASN
    trust_asn = bool(latest and latest.result.net and run.net and latest.result.net.asn
                     and latest.result.net.asn == run.net.asn)
    verdict = decide(run, base.result if base else None, mode, trust_asn=trust_asn)
    diff = compare(run, base) if base and verdict.code not in ("no_data", "vpn") else None
    valid = run.complete and verdict.code not in ("no_data", "vpn") and mode != "sni"
    return RunRecord(
        timestamp=now.strftime("%Y-%m-%dT%H:%M:%S"), mode=mode, net=net, net_raw=net_raw,
        engine_commit=_engine_commit(), wrapper_version=__version__, result=run, verdict=verdict,
        base_timestamp=base.timestamp if base else None, diff=diff, valid_base=valid,
    )


def _fallback_record(mode: str, net_raw: str, now: datetime, err: BaseException) -> RunRecord:
    v = Verdict("no_data", TEXT["no_data"], facts=["Ошибка обёртки: " + type(err).__name__])
    return RunRecord(timestamp=now.strftime("%Y-%m-%dT%H:%M:%S"), mode=mode, net=sanitize(net_raw),
                     net_raw=net_raw, engine_commit=_engine_commit(), wrapper_version=__version__,
                     result=RunResult(complete=False), verdict=v)


def _log_header(rec: RunRecord, partial: bool) -> str:
    lines = ["# DPI Logs", "# Дата: " + rec.timestamp, "# Режим: " + rec.mode + " (тесты " + MODE_TESTS.get(rec.mode, "?") + ")",
             "# Сеть: " + rec.net_raw, "# Движок: dpi-detector " + rec.engine_commit,
             "# Обёртка: dpiphone " + rec.wrapper_version]
    if partial or not rec.result.complete:
        lines.append("# НЕПОЛНЫЙ ЛОГ")
    return "\n".join(lines) + "\n\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=sorted(MODE_TESTS), required=True)
    ap.add_argument("--net", default="")
    ap.add_argument("--out", default="out")
    ap.add_argument("--history", default="history")
    ap.add_argument("--engine", default="../dpi-detector")
    args = ap.parse_args(argv)

    out, hist, engine = Path(args.out), Path(args.history), Path(args.engine)
    out.mkdir(parents=True, exist_ok=True)
    now = datetime.now()
    text, partial = _read_engine_log(out)

    try:
        rec = build_record(text, args.mode, args.net, hist, engine, now)
        summary = render(rec)
    except Exception as err:  # noqa: BLE001 — любой сбой обёртки не должен оставить Команду без файлов
        traceback.print_exc(file=sys.stderr)
        rec = _fallback_record(args.mode, args.net, now, err)
        summary = rec.verdict.text + "\n" + rec.verdict.facts[0]

    stem = file_stem(rec.timestamp, rec.mode, rec.net)
    (out / "summary.txt").write_text(summary + "\n", encoding="utf-8")
    (out / "name.txt").write_text(stem, encoding="utf-8")   # без перевода строки: Команда подставляет его в имя файла
    data = asdict(rec)
    data["summary"] = summary
    (out / "last.json").write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    (out / "last.log").write_text(_log_header(rec, partial) + text, encoding="utf-8")
    try:
        history.save(hist, rec)
    except OSError:
        traceback.print_exc(file=sys.stderr)
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
