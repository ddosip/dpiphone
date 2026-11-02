"""Короткий отчёт: вердикт, пустая строка, факты."""

from __future__ import annotations

from typing import List

from dpiphone.buckets import bucket
from dpiphone.model import RunRecord, RunResult
from dpiphone.modes import MODE_SECTIONS
from dpiphone.verdict import _domain_bucket, detected_providers, dns_substituted

NOT_RUN = "не выполнен"


def _net_line(r: RunResult, net_raw: str) -> str:
    if r.net is None:
        return "Сеть: " + NOT_RUN
    parts = [net_raw]
    op = " ".join(p for p in (r.net.asn, r.net.org) if p)
    if op:
        parts.append(op)
    if r.net.ipv4:
        parts.append(r.net.ipv4)
    return "Сеть: " + " · ".join(parts)


def _dns_line(r: RunResult) -> str:
    d = r.dns
    if d is None or (d.udp_total == 0 and d.doh_total == 0):
        return "DNS: " + NOT_RUN
    head = "DNS: {}/{} UDP, {}/{} DoH".format(d.udp_ok, d.udp_total, d.doh_ok, d.doh_total)
    if d.hijacked_all:
        tail = "подмена резолвера у всех"
    elif len(d.hijacked_brands) >= 2:
        tail = "подмена резолвера: " + ", ".join(d.hijacked_brands)
    elif dns_substituted(r):
        tail = "подмена ответов у {}/{} UDP (перехват порта 53)".format(d.subst_sub, d.subst_total)
    else:
        tail = "подмены нет"
    return head + " · " + tail


def _domains_line(r: RunResult) -> str:
    if r.domains is None:
        return "Сайты: " + NOT_RUN
    kinds = [_domain_bucket(d) for d in r.domains]
    ok = sum(1 for k in kinds if k == "noise")
    parts = ["Сайты: {}/{} OK".format(ok, len(kinds))]
    blocked = sum(1 for k in kinds if k == "block")
    channel = sum(1 for k in kinds if k == "channel")
    if blocked:
        parts.append("блок {}".format(blocked))
    if channel:
        parts.append("дроп/таймаут {}".format(channel))
    return " · ".join(parts)


def _tcp_line(r: RunResult) -> str:
    if r.tcp is None:
        return "Хостинги 16–20 КБ: " + NOT_RUN
    ok = sum(1 for t in r.tcp if bucket(t.status) == "noise" and t.status.upper().startswith("OK"))
    bad = sorted(detected_providers(r))
    return "Хостинги 16–20 КБ: {}/{} OK · обрыв: {}".format(ok, len(r.tcp), ", ".join(bad) if bad else "нет")


def _telegram_line(r: RunResult) -> str:
    t = r.telegram
    if t is None:
        return "Telegram: " + NOT_RUN
    return "Telegram: скачивание {}, загрузка {}, ДЦ {}/{}".format(t.download, t.upload, t.dc_ok, t.dc_total)


def _sni_line(r: RunResult) -> str:
    s = r.sni
    if s is None:
        return "Белые SNI: " + NOT_RUN
    if s.blocked_as == 0:
        return "Белые SNI: не нужны, обрывов нет"
    if s.found_as > 0:
        return "Белые SNI: найдены для {} из {} провайдеров".format(s.found_as, s.blocked_as)
    return "Белые SNI: не найдены ({} провайдеров)".format(s.blocked_as)


_SECTION = {
    "net": None, "dns": _dns_line, "domains": _domains_line, "tcp": _tcp_line,
    "telegram": _telegram_line, "sni": _sni_line,
}


def _when(ts: str) -> str:
    """'2026-11-01T19:40:00' → '01.11 19:40'."""
    try:
        date, time = ts.split("T")
        y, m, d = date.split("-")
        return "{}.{} {}".format(d, m, time[:5])
    except ValueError:
        return ts


def _compare_line(rec: RunRecord) -> str:
    if rec.diff is None:
        return "Первый прогон на этой сети"
    head = "Прошлый прогон на {} ({}): ".format(rec.net_raw, _when(rec.diff.base_timestamp))
    if rec.diff.is_empty():
        return head + "без изменений"
    added: List[str] = list(rec.diff.domains_added) + ["обрыв " + p for p in rec.diff.providers_added]
    removed: List[str] = list(rec.diff.domains_removed) + ["обрыв " + p for p in rec.diff.providers_removed]
    if rec.diff.dns_changed == "появилась":
        added.append("подмена DNS")
    elif rec.diff.dns_changed == "исчезла":
        removed.append("подмена DNS")
    parts = []
    if added:
        parts.append("появилось: " + ", ".join(added))
    if removed:
        parts.append("исчезло: " + ", ".join(removed))
    return head + " / ".join(parts)


def render(rec: RunRecord) -> str:
    r = rec.result
    lines = [rec.verdict.text, ""]
    if not r.complete:
        lines.append("Лог неполный: движок не дошёл до конца")
    for name in MODE_SECTIONS.get(rec.mode, MODE_SECTIONS["quick"]):
        if name == "net":
            lines.append(_net_line(r, rec.net_raw))
        else:
            lines.append(_SECTION[name](r))
    if rec.mode != "sni":
        lines.append(_compare_line(rec))
    return "\n".join(lines)
