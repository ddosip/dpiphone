"""Модель данных: результат прогона движка, вердикт, запись истории."""

from __future__ import annotations

import re
from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Optional


@dataclass
class NetInfo:
    ipv4: Optional[str]
    ipv6: Optional[str]
    org: Optional[str]
    asn: Optional[str]            # "AS197540"
    country: Optional[str]
    system_dns: List[str] = field(default_factory=list)
    fakeip_system_dns: bool = False   # "(fake-ip)" у системного DNS


@dataclass
class DnsResult:
    doh_ok: int = 0
    doh_total: int = 0
    dot_ok: int = 0
    dot_total: int = 0
    udp_ok: int = 0
    udp_total: int = 0
    hijacked_brands: List[str] = field(default_factory=list)
    hijacked_all: bool = False
    subst_sub: int = 0
    subst_total: int = 0
    fakeip_sub: int = 0
    isp_intercept_warning: bool = False
    fakeip_warning: bool = False


@dataclass
class DomainResult:
    domain: str
    http: str
    tls12: str
    tls13: str
    detail: str = ""


_NON_WORD = re.compile(r"[^\w\s.-]")


@dataclass
class TcpTarget:
    id: str
    asn: str
    provider: str
    status: str
    detail: str = ""

    @property
    def provider_group(self) -> str:
        """Первое слово провайдера без знаков: 'Hetzner Cloud 2' → 'Hetzner'."""
        clean = _NON_WORD.sub("", self.provider).strip()
        parts = clean.split()
        return parts[0] if parts else clean


@dataclass
class TelegramResult:
    download: str          # ОК | ЗАМЕДЛЕНИЕ | ЗАМЕДЛЕНИЕ+ОБРЫВ | НЕДОСТУПНО | ОШИБКА
    upload: str
    dc_ok: int
    dc_total: int


@dataclass
class SniResult:
    found_as: int
    blocked_as: int
    per_provider: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class RunResult:
    complete: bool
    net: Optional[NetInfo] = None
    dns: Optional[DnsResult] = None
    domains: Optional[List[DomainResult]] = None
    fakeip_domains: int = 0
    tcp: Optional[List[TcpTarget]] = None
    telegram: Optional[TelegramResult] = None
    sni: Optional[SniResult] = None


@dataclass
class Verdict:
    code: str      # no_data | vpn | dns_new | whitelist | dns_and_whitelist | new_blocks | channel | ok
    text: str
    facts: List[str] = field(default_factory=list)


@dataclass
class Diff:
    base_timestamp: str
    dns_changed: Optional[str] = None          # None | "появилась" | "исчезла"
    domains_added: List[str] = field(default_factory=list)
    domains_removed: List[str] = field(default_factory=list)
    providers_added: List[str] = field(default_factory=list)
    providers_removed: List[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.dns_changed or self.domains_added or self.domains_removed
                    or self.providers_added or self.providers_removed)


@dataclass
class RunRecord:
    timestamp: str          # "2026-11-02T14:32:05", локальное время
    mode: str
    net: str
    net_raw: str
    engine_commit: str
    wrapper_version: str
    result: RunResult
    verdict: Verdict
    base_timestamp: Optional[str] = None
    diff: Optional[Diff] = None
    valid_base: bool = False


_CLASSES = {
    "NetInfo": NetInfo, "DnsResult": DnsResult, "DomainResult": DomainResult, "TcpTarget": TcpTarget,
    "TelegramResult": TelegramResult, "SniResult": SniResult, "RunResult": RunResult,
    "Verdict": Verdict, "Diff": Diff,
}
_LIST_RE = re.compile(r"List\[(\w+)\]")
_NAME_RE = re.compile(r"\b(\w+)\b")


def _build(cls: Any, data: Any) -> Any:
    """Восстанавливает dataclass из словаря по строковым аннотациям полей."""
    if data is None:
        return None
    kwargs = {}
    for f in fields(cls):
        if f.name not in data:
            continue
        v = data[f.name]
        hint = f.type if isinstance(f.type, str) else getattr(f.type, "__name__", "")
        m = _LIST_RE.search(hint)
        if m and m.group(1) in _CLASSES and v is not None:
            v = [_build(_CLASSES[m.group(1)], x) for x in v]
        else:
            inner = next((n for n in _NAME_RE.findall(hint) if n in _CLASSES), None)
            if inner is not None and isinstance(v, dict):
                v = _build(_CLASSES[inner], v)
        kwargs[f.name] = v
    return cls(**kwargs)


def record_from_dict(d: Dict[str, Any]) -> RunRecord:
    """Обратное к dataclasses.asdict для RunRecord."""
    return _build(RunRecord, d)
