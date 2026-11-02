"""История прогонов: по одному JSON на прогон, выбор базы для сравнения."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import List, Optional

from dpiphone.model import RunRecord, record_from_dict


def save(history_dir: Path, record: RunRecord) -> Path:
    history_dir = Path(history_dir)
    history_dir.mkdir(parents=True, exist_ok=True)
    name = "{}_{}_{}.json".format(record.timestamp.replace(":", "-"), record.mode, record.net)
    path = history_dir / name
    path.write_text(json.dumps(asdict(record), ensure_ascii=False, indent=1), encoding="utf-8")
    return path


def load_all(history_dir: Path) -> List[RunRecord]:
    """Все читаемые записи истории; битые файлы пропускаются."""
    out: List[RunRecord] = []
    history_dir = Path(history_dir)
    if not history_dir.is_dir():
        return out
    for p in sorted(history_dir.glob("*.json")):
        try:
            out.append(record_from_dict(json.loads(p.read_text(encoding="utf-8"))))
        except (ValueError, TypeError, KeyError):
            continue
    return out


def find_latest(history_dir: Path, net: str) -> Optional[RunRecord]:
    """Последний прогон на сети, годный или нет."""
    same = [r for r in load_all(history_dir) if r.net == net]
    return max(same, key=lambda r: r.timestamp) if same else None


def find_base(history_dir: Path, net: str) -> Optional[RunRecord]:
    """Последний полноценный прогон на сети с тем же именем."""
    candidates = [r for r in load_all(history_dir) if r.net == net and r.valid_base]
    if not candidates:
        return None
    return max(candidates, key=lambda r: r.timestamp)
