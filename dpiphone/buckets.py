"""Корзины статусов движка: блокировка, канал, шум."""

from __future__ import annotations

import re

BLOCK = {
    "TLS RST", "TCP RST", "TLS ALERT", "TLS BLOCK", "TLS SPOOF", "TLS EOF",
    "TLS MITM", "TLS ABORT", "TCP ABORT", "BLOCKED", "ISP PAGE", "DNS FAKE",
    "DETECTED",
}
CHANNEL = {
    "TLS DROP", "SYN DROP", "TIMEOUT", "READ TIMEOUT", "SEND TIMEOUT",
    "POOL TIMEOUT", "NET UNREACH", "HOST UNREACH",
}

_TAIL = re.compile(r"\s*[(…].*$")


def normalize(status: str) -> str:
    """Статус движка без хвостов: верхний регистр, без скобок и обрезанных слов."""
    s = _TAIL.sub("", (status or "").strip().upper())
    if s.startswith("UNKNOWN"):
        return "UNKNOWN"
    return s.strip()


def bucket(status: str, detail: str = "") -> str:
    """'block' | 'channel' | 'noise' для статуса движка и его деталей."""
    s = normalize(status)
    if s == "REDIR":
        return "block" if "→" in (detail or "") else "noise"
    if s in BLOCK:
        return "block"
    if s in CHANNEL:
        return "channel"
    return "noise"
