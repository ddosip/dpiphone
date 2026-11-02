"""Разбор текстового лога dpi-detector в RunResult.

Опирается на формат вывода движка v4.2.4: панель «Информация о сети и системе»,
таблицы тестов 2 и 3 (rich, рамки │ ┃ ┏ └), строки теста 4, панель «Итог».
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional

from dpiphone.model import (
    DnsResult, DomainResult, NetInfo, RunResult, SniResult, TcpTarget, TelegramResult,
)

_IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
_ORG_RE = re.compile(r"Org:\s*(.*?)\s*\(AS(\d+)\)\s*$")
_COUNTRY_RE = re.compile(r"\b([A-Z]{2})\b")

_SUM_DNS = re.compile(r"DNS доступность\s+(\d+)/(\d+) DoH(?:\s+(\d+)/(\d+) DoT)?\s+(\d+)/(\d+) UDP")
_SUM_HIJACK = re.compile(r"Подмена резолвера\s+(.+?)\s*$")
_SUM_SUBST = re.compile(r"Подмена ответов\s+у (\d+)/(\d+) UDP")
_SUM_FAKEIP = re.compile(r"FakeIP ответов\s+у (\d+)/(\d+) UDP")
_SUM_TG_DL = re.compile(r"TG Скачивание\s+(\S+)")
_SUM_TG_UL = re.compile(r"TG Загрузка\s+(\S+)")
_SUM_TG_DC = re.compile(r"TG Датацентры\s+\S+ (\d+)/(\d+)")

_FAKEIP_DOMAINS = re.compile(r"Трафик перехватывается Fake-IP: у (\d+) доменов")
_SNI_ROW = re.compile(r"^\s{2}(.+?) (AS\d+\S*)\s+([✓×⚠])\s*(.*)$")
_SNI_FOUND = re.compile(r"Найдено белых SNI: у (\d+) из (\d+) заблокированных AS")
_SNI_NONE = re.compile(r"Белые SNI не найдены ни для одной из (\d+) заблокированных AS")
_SNI_NOT_NEEDED = "Ни одна AS не заблокирована"

_SUMMARY_LABELS = ("DNS доступность", "Подмена резолвера", "Подмена ответов", "FakeIP ответов",
                   "Домены", "TCP 16-20KB", "TG Скачивание", "TG Загрузка", "TG Датацентры")
_ISP_WARNING = "[!] Ваш интернет-провайдер перехватывает DNS-запросы"
_FAKEIP_WARNING = "[!] DNS-ответы содержат FakeIP"
_DNS_HEADER = "Проверка доступности DNS-серверов"


def load_known_domains(engine_dir: Path) -> List[str]:
    """Список доменов движка из domains.txt, очищенный как clean_hostname движка."""
    path = Path(engine_dir) / "domains.txt"
    if not path.exists():
        return []
    out: List[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        s = raw.strip().lower()
        if not s or s.startswith("#"):
            continue
        s = s.split("://", 1)[-1]
        s = s.split("/", 1)[0]
        if s.count(":") < 2:
            s = s.split(":", 1)[0]
        out.append(s.strip("[]"))
    return out


def _cells(line: str) -> List[str]:
    """Ячейки строки таблицы rich: '│ a │ b │' → ['a', 'b']."""
    inner = line.strip()
    if inner.startswith("│"):
        inner = inner[1:]
    if inner.endswith("│"):
        inner = inner[:-1]
    return [c.strip() for c in inner.split("│")]


def _restore_domain(name: str, known: List[str]) -> str:
    if not name.endswith("…"):
        return name
    prefix = name[:-1]
    candidates = [d for d in known if d.startswith(prefix)]
    return candidates[0] if len(candidates) == 1 else name


class _Parser:
    def __init__(self, known_domains: List[str]):
        self.known = known_domains
        self.section = ""                 # netinfo | domains | tcp | summary | ""
        self.net_lines: List[str] = []
        self.domain_rows: List[List[str]] = []
        self.tcp_rows: List[List[str]] = []
        self.summary_lines: List[str] = []
        self.saw_domains_table = False
        self.saw_tcp_table = False
        self.saw_dns = False
        self.complete = False
        self.isp_warning = False
        self.fakeip_warning = False
        self.fakeip_domains = 0
        self.sni_rows: Dict[str, List[str]] = {}
        self.sni_found: Optional[int] = None
        self.sni_blocked: Optional[int] = None
        self.saw_sni = False
        self.truncated = False

    # ── строки ────────────────────────────────────────────────────────────
    def feed(self, line: str) -> None:
        s = line.rstrip()
        if "Информация о сети и системе" in s:
            self.section = "netinfo"
            return
        if "┃ Домен" in s:
            self.section, self.saw_domains_table = "domains", True
            return
        if "┃ ID " in s:
            self.section, self.saw_tcp_table = "tcp", True
            return
        if "╭" in s and "Итог" in s:
            self.section, self.complete = "summary", True
            return

        if self.section == "netinfo":
            if s.startswith("╰"):
                self.section = ""
            elif s.startswith("│"):
                self.net_lines.append(s.strip("│ ").strip())
            return
        if self.section == "summary":
            if s.startswith("╰"):
                self.section = ""
            elif s.startswith("│"):
                cell = s.strip("│ ").strip()
                if cell.startswith(_SUMMARY_LABELS) or not self.summary_lines:
                    self.summary_lines.append(cell)
                else:   # перенос строки панели на узком терминале
                    self.summary_lines[-1] += " " + cell
            return
        if self.section in ("domains", "tcp"):
            if s.startswith("└"):
                self.section = ""
                return
            if s.startswith("│"):
                self._table_row(_cells(s))
            return

        self._loose_line(s)

    def _table_row(self, cells: List[str]) -> None:
        rows = self.domain_rows if self.section == "domains" else self.tcp_rows
        if len(cells) != 5:
            return
        if cells[0]:
            status_cells = cells[1:4] if self.section == "domains" else cells[3:4]
            if any("…" in c for c in status_cells):
                self.truncated = True
            rows.append(cells)
            return
        if not rows:
            return
        prev = rows[-1]
        for i, c in enumerate(cells):
            if c:
                prev[i] = (prev[i] + " " + c).strip()

    def _loose_line(self, s: str) -> None:
        if _DNS_HEADER in s:
            self.saw_dns = True
        if _ISP_WARNING in s:
            self.isp_warning = True
        if _FAKEIP_WARNING in s:
            self.fakeip_warning = True
        m = _FAKEIP_DOMAINS.search(s)
        if m:
            self.fakeip_domains = int(m.group(1))
        m = _SNI_FOUND.search(s)
        if m:
            self.saw_sni = True
            self.sni_found, self.sni_blocked = int(m.group(1)), int(m.group(2))
            return
        m = _SNI_NONE.search(s)
        if m:
            self.saw_sni = True
            self.sni_found, self.sni_blocked = 0, int(m.group(1))
            return
        if _SNI_NOT_NEEDED in s:
            self.saw_sni = True
            self.sni_found, self.sni_blocked = 0, 0
            return
        m = _SNI_ROW.match(s)
        if m:
            self.saw_sni = True
            provider, mark, rest = m.group(1).strip(), m.group(3), m.group(4)
            found: List[str] = []
            if mark == "✓":
                for token in re.split(r"\s{2,}", rest.strip()):
                    token = re.sub(r"\s*#\d+$", "", token).strip()
                    if token and token != "⚠ бан после":
                        found.append(token)
            self.sni_rows[provider] = found

    # ── сборка ────────────────────────────────────────────────────────────
    def net(self) -> Optional[NetInfo]:
        if not self.net_lines:
            return None
        ipv4 = ipv6 = org = asn = country = None
        system_dns: List[str] = []
        fakeip = False
        for l in self.net_lines:
            if l.startswith("IPv4:"):
                m = re.match(r"IPv4:\s*(\S+)", l)
                if m and m.group(1) != "недоступен" and _IP_RE.match(m.group(1)):
                    ipv4 = m.group(1)
            elif l.startswith("IPv6:"):
                m = re.match(r"IPv6:\s*(\S+)", l)
                if m and m.group(1) != "недоступен" and ":" in m.group(1):
                    ipv6 = m.group(1)
            elif l.startswith("Org:"):
                m = _ORG_RE.search(l)
                if m:
                    org, asn = m.group(1), "AS" + m.group(2)
                else:
                    rest = l[4:].strip()
                    org = rest if rest and rest != "…" else None
            elif l.startswith("Location:"):
                m = _COUNTRY_RE.search(l)
                country = m.group(1) if m else None
            elif l.startswith("Системный DNS:"):
                system_dns.extend(_IP_RE.findall(l))
                if "(fake-ip)" in l:
                    fakeip = True
        return NetInfo(ipv4=ipv4, ipv6=ipv6, org=org, asn=asn, country=country,
                       system_dns=system_dns, fakeip_system_dns=fakeip)

    def dns(self) -> Optional[DnsResult]:
        if not (self.saw_dns or self.isp_warning or self.fakeip_warning
                or any("DNS доступность" in l for l in self.summary_lines)):
            return None
        d = DnsResult(isp_intercept_warning=self.isp_warning, fakeip_warning=self.fakeip_warning)
        for l in self.summary_lines:
            m = _SUM_DNS.search(l)
            if m:
                d.doh_ok, d.doh_total = int(m.group(1)), int(m.group(2))
                if m.group(3) is not None:
                    d.dot_ok, d.dot_total = int(m.group(3)), int(m.group(4))
                d.udp_ok, d.udp_total = int(m.group(5)), int(m.group(6))
                continue
            m = _SUM_HIJACK.search(l)
            if m:
                v = m.group(1).strip()
                if v == "Все":
                    d.hijacked_all = True
                elif v not in ("—", "-", ""):
                    d.hijacked_brands = [b.strip() for b in v.split(",") if b.strip()]
                continue
            m = _SUM_SUBST.search(l)
            if m:
                d.subst_sub, d.subst_total = int(m.group(1)), int(m.group(2))
                continue
            m = _SUM_FAKEIP.search(l)
            if m:
                d.fakeip_sub = int(m.group(1))
                d.subst_total = d.subst_total or int(m.group(2))
        return d

    def domains(self) -> Optional[List[DomainResult]]:
        if not self.saw_domains_table:
            return None
        return [DomainResult(domain=_restore_domain(r[0], self.known), http=r[1],
                             tls12=r[2], tls13=r[3], detail=r[4]) for r in self.domain_rows]

    def tcp(self) -> Optional[List[TcpTarget]]:
        if not self.saw_tcp_table:
            return None
        return [TcpTarget(id=r[0], asn=r[1].replace("☆", "").strip(), provider=r[2],
                          status=r[3], detail=r[4]) for r in self.tcp_rows]

    def telegram(self) -> Optional[TelegramResult]:
        dl = ul = None
        dc_ok = dc_total = 0
        for l in self.summary_lines:
            m = _SUM_TG_DL.search(l)
            if m:
                dl = m.group(1)
            m = _SUM_TG_UL.search(l)
            if m:
                ul = m.group(1)
            m = _SUM_TG_DC.search(l)
            if m:
                dc_ok, dc_total = int(m.group(1)), int(m.group(2))
        if dl is None and ul is None:
            return None
        return TelegramResult(download=dl or "ОШИБКА", upload=ul or "ОШИБКА",
                              dc_ok=dc_ok, dc_total=dc_total)

    def sni(self) -> Optional[SniResult]:
        if not self.saw_sni:
            return None
        return SniResult(found_as=self.sni_found or 0, blocked_as=self.sni_blocked or 0,
                         per_provider=dict(self.sni_rows))


def parse_log(text: str, known_domains: List[str]) -> RunResult:
    """Разбирает лог движка (raw.log из -o или console.log из stdout)."""
    p = _Parser(known_domains)
    for line in text.replace("\r", "\n").splitlines():
        p.feed(line)
    return RunResult(
        complete=p.complete,
        net=p.net(),
        dns=p.dns(),
        domains=p.domains(),
        fakeip_domains=p.fakeip_domains,
        tcp=p.tcp(),
        telegram=p.telegram(),
        sni=p.sni(),
        truncated=p.truncated,
    )
