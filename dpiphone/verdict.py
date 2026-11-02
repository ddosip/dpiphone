"""Правила вердикта. Проверяются по порядку, первое сработавшее побеждает.

Пороги только из thresholds.py. При сомнении правила молчат, и вердикт «всё в порядке».
"""

from __future__ import annotations

from typing import List, Optional, Set

from dpiphone import thresholds as T
from dpiphone.buckets import bucket
from dpiphone.model import RunResult, Verdict

TEXT = {
    "no_data": "Сеть почти не отвечает, проверить не удалось",
    "truncated": "Лог нечитаем: таблицы обрезаны, нужна ширина терминала не меньше 80 колонок",
    "vpn": "Похоже, включён VPN или прокси, прогон не о вашем операторе",
    "dns_and_whitelist": "Смешанная картина: подмена DNS и белый список",
    "dns_new": "Оператор начал подменять DNS",
    "channel": "Блокировок не вижу, похоже на качество канала",
    "ok": "Всё в порядке",
}


# ── чистые функции над RunResult (их же использует compare.py) ──────────────

def _domain_bucket(d) -> str:
    """Худшая корзина по трём колонкам домена: block > channel > noise."""
    kinds = {bucket(s, d.detail) for s in (d.http, d.tls12, d.tls13)}
    if "block" in kinds:
        return "block"
    if "channel" in kinds:
        return "channel"
    return "noise"


def blocked_domains(run: RunResult) -> Set[str]:
    return {d.domain for d in (run.domains or []) if _domain_bucket(d) == "block"}


def _target_buckets(run: RunResult) -> List[str]:
    out = [_domain_bucket(d) for d in (run.domains or [])]
    out += [bucket(t.status, t.detail) for t in (run.tcp or [])]
    return out


def channel_share(run: RunResult) -> float:
    kinds = _target_buckets(run)
    if not kinds:
        return 0.0
    return sum(1 for k in kinds if k == "channel") / len(kinds)


def _has_block(run: RunResult) -> bool:
    return any(k == "block" for k in _target_buckets(run))


def detected_providers(run: RunResult) -> Set[str]:
    """Провайдеры (по первому слову), у которых все цели теста 3 — DETECTED."""
    groups = {}
    for t in run.tcp or []:
        groups.setdefault(t.provider_group, []).append(bucket(t.status) == "block" and "DETECTED" in t.status.upper())
    return {g for g, flags in groups.items() if flags and all(flags)}


def _detected_share(run: RunResult) -> float:
    tcp = run.tcp or []
    if not tcp:
        return 0.0
    return sum(1 for t in tcp if "DETECTED" in t.status.upper()) / len(tcp)


def dns_substituted(run: RunResult) -> bool:
    d = run.dns
    if d is None:
        return False
    return (d.hijacked_all
            or len(d.hijacked_brands) >= T.DNS_SUBST_MIN_RESOLVERS
            or d.subst_sub >= T.DNS_SUBST_MIN_RESOLVERS)


def _fakeip(run: RunResult) -> bool:
    return bool((run.net and run.net.fakeip_system_dns)
                or run.fakeip_domains > 0
                or (run.dns and run.dns.fakeip_warning))


# ── правила ──────────────────────────────────────────────────────────────────

def _whitelist(run: RunResult) -> bool:
    return (_detected_share(run) >= T.WHITELIST_MIN_SHARE
            and len(detected_providers(run)) >= T.WHITELIST_MIN_PROVIDERS)


def _whitelist_text(run: RunResult) -> str:
    bad = sorted(detected_providers(run))
    good = sorted({t.provider_group for t in (run.tcp or [])} - set(bad))
    text = "Похоже, включён белый список: обрываются " + ", ".join(bad)
    if good:
        text += "; в норме " + ", ".join(good)
    return text


def _same_operator(a: Optional[str], b: Optional[str]) -> bool:
    """Первое слово org совпадает: MTS PJSC и MTS Yug это один оператор с разными ASN."""
    fa, fb = (a or "").split(" ")[0].upper(), (b or "").split(" ")[0].upper()
    return bool(fa) and fa == fb


def decide(run: RunResult, base: Optional[RunResult], mode: str = "quick", trust_asn: bool = False) -> Verdict:
    """trust_asn: ASN уже подтверждён повторным прогоном, расхождение с базой не считать VPN."""
    if run.truncated:
        return Verdict("no_data", TEXT["truncated"])
    if mode == "sni":
        if not run.complete:
            return Verdict("no_data", TEXT["no_data"])
        if _whitelist(run):
            return Verdict("whitelist", _whitelist_text(run))
        return Verdict("ok", TEXT["ok"])

    # 0а. Нет данных
    if (not run.complete or run.net is None or run.net.ipv4 is None
            or (channel_share(run) >= T.NO_DATA_CHANNEL_SHARE and not _has_block(run))):
        return Verdict("no_data", TEXT["no_data"])

    # 0б. VPN или прокси
    asn_differs = (base is not None and base.net is not None and base.net.asn and run.net.asn
                   and base.net.asn != run.net.asn and not _same_operator(base.net.org, run.net.org))
    if _fakeip(run) or (asn_differs and not trust_asn):
        return Verdict("vpn", TEXT["vpn"])

    dns_new = dns_substituted(run) and base is not None and not dns_substituted(base)
    whitelist = _whitelist(run)

    if dns_new and whitelist:
        return Verdict("dns_and_whitelist", TEXT["dns_and_whitelist"])
    if dns_new:
        return Verdict("dns_new", TEXT["dns_new"])
    if whitelist:
        return Verdict("whitelist", _whitelist_text(run))

    # 3. Новые блокировки относительно базы
    if base is not None:
        added = sorted(blocked_domains(run) - blocked_domains(base))
        if len(added) >= T.NEW_BLOCKS_MIN:
            return Verdict("new_blocks", "Появились новые блокировки: " + ", ".join(added))

    # 4. Плохой канал
    tg_bad = run.telegram is not None and (run.telegram.download != "ОК" or run.telegram.upload != "ОК")
    if channel_share(run) >= T.CHANNEL_MIN_SHARE or tg_bad:
        return Verdict("channel", TEXT["channel"])

    return Verdict("ok", TEXT["ok"])
