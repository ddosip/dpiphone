"""Имя сети для имени файла."""

from __future__ import annotations

import re

_BAD = re.compile(r"[^A-Za-z0-9_-]+")


def sanitize(net_raw: str) -> str:
    """Только [A-Za-z0-9_-], подряд идущие '_' схлопнуты, пусто → 'unknown', не длиннее 40."""
    s = _BAD.sub("_", net_raw or "")
    s = re.sub(r"_+", "_", s).strip("_")
    return (s or "unknown")[:40]


def file_stem(timestamp: str, mode: str, net: str) -> str:
    """'2026-11-02T14:32:05', 'quick', 'MTS' → '2026-11-02_14-32_quick_MTS'."""
    ts = timestamp[:16].replace("T", "_").replace(":", "-")
    return "{}_{}_{}".format(ts, mode, net)
