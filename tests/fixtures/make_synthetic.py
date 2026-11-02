"""Генератор синтетических фикстур из реального лога mac_vpn_quick.raw.log.

Запуск из корня проекта: python tests/fixtures/make_synthetic.py (нужен пакет rich, как у движка).
"""
import re, sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

FIX = Path("tests/fixtures")
real = (FIX / "mac_vpn_quick.raw.log").read_text(encoding="utf-8").splitlines()
NET, DNS, DOM_HDR, TCP_HDR = real[0:9], real[9:177], real[178:180], real[224:225]

def render(renderable, width=80):
    c = Console(record=True, width=width, file=open("/dev/null", "w"), force_terminal=False)
    c.print(renderable)
    return c.export_text().rstrip("\n").splitlines()

def panel_line(line, old, new):
    """Замена внутри строки рамки с сохранением ширины."""
    assert old in line, old
    inner = line[1:-1].replace(old, new)
    width = len(line) - 2
    inner = inner[:width].ljust(width)
    return line[0] + inner + line[-1]

def domains_table(rows):
    t = Table(show_header=True, header_style="bold magenta", border_style="dim")
    t.add_column("Домен", style="cyan", no_wrap=True, width=18)
    for c in ("HTTP", "TLS1.2", "TLS1.3"):
        t.add_column(c, justify="center")
    t.add_column("Детали", style="dim", no_wrap=True)
    for r in rows:
        t.add_row(*r)
    return render(t)

def tcp_table(rows):
    t = Table(show_header=True, header_style="bold magenta", border_style="dim")
    t.add_column("ID", style="white"); t.add_column("ASN", style="yellow")
    t.add_column("Провайдер", style="cyan"); t.add_column("Статус", justify="center")
    t.add_column("Детали", style="dim")
    for r in rows:
        t.add_row(*r)
    return render(t)

def summary_panel(items):
    t = Table(show_header=False, box=None, pad_edge=False)
    t.add_column(no_wrap=True); t.add_column()
    for lab, val in items:
        t.add_row(f"[bold]{lab}[/bold]", val)
    return render(Panel(t, title="[bold]Итог[/bold]", border_style="cyan", padding=(0, 1), expand=False))

# Реальные строки TCP (id, asn, provider) из лога
tcp_real = []
for line in real[228:351]:
    cells = [c.strip() for c in line.strip("│").split("│")]
    if len(cells) == 5 and cells[0]:
        tcp_real.append((cells[0], cells[1], cells[2]))
assert len(tcp_real) == 110, len(tcp_real)
DOMAINS = []
for line in real[183:220]:
    cells = [c.strip() for c in line.strip("│").split("│")]
    if len(cells) == 5 and cells[0]:
        DOMAINS.append(cells[0])
assert len(DOMAINS) == 36
FULL = {"media.discordapp.…": "media.discordapp.net", "www.themoscowtime…": "www.themoscowtimes.com"}
DOMAINS = [FULL.get(d, d) for d in DOMAINS]
WL_PREFIX = ("HE-", "CF-", "AWS-", "CDN-", "CNT-", "OVH-", "DO-", "OR-")

def net_block(asn_line, fakeip):
    out = list(NET)
    out[4] = panel_line(out[4], "netcup-AS - netcup GmbH, DE (AS197540)", asn_line)
    if not fakeip:
        out[6] = panel_line(out[6], "198.18.0.2 (fake-ip)", "192.168.1.1")
        out[7] = panel_line(out[7], "198.18.0.43", "10.0.0.1")
    return out

def dom_rows(blocked=(), all_status=None):
    rows = []
    for d in DOMAINS:
        if all_status:
            rows.append((d, all_status, all_status, all_status, "Connect timeout"))
        elif d in blocked:
            rows.append((d, "OK", "TLS RST", "TLS RST", "TCP RST на ClientHello"))
        else:
            rows.append((d, "OK", "OK", "OK", "0.8s"))
    return rows

def tcp_rows(detected_prefixes=(), all_status=None):
    rows = []
    for id_, asn, prov in tcp_real:
        if all_status:
            rows.append((id_, asn, prov, all_status, "TLS Handshake timeout | 8.0s"))
        elif id_.startswith(detected_prefixes):
            rows.append((id_, asn, prov, "DETECTED", "RST at 18KB"))
        else:
            rows.append((id_, asn, prov, "OK", "3.1s"))
    return rows

def dns_block(hijack=False, fakeip=True):
    out = list(DNS)
    if not fakeip:
        pass
    if hijack:
        return out
    # без VPN и без перехвата: убираем предупреждение
    i = next(k for k, l in enumerate(out) if "перехватывает DNS-запросы" in l)
    return out[:i - 1] + out[i + 3:]

def assemble(net, dns, doms, fakeip_line, tcp, extra, summary):
    lines = net + dns + DOM_HDR + domains_table(doms) + [""]
    if fakeip_line:
        lines += ["[!] ИНФОРМАЦИЯ О DNS РЕЗОЛВЕ:", fakeip_line, ""]
    lines += TCP_HDR + tcp_table(tcp) + [""] + extra + summary_panel(summary) + [""]
    return "\n".join(lines) + "\n"

ok_dns = [("DNS доступность", "36/36 DoH  32/33 DoT  35/37 UDP"), ("Подмена резолвера", "—"), ("Подмена ответов", "у 0/35 UDP")]
MTS = "MTS PJSC (AS8359)"

wl_dom = dom_rows(blocked={"www.youtube.com", "discord.com", "www.instagram.com"})
wl_tcp = tcp_rows(WL_PREFIX)
n_det = sum(1 for r in wl_tcp if r[3] == "DETECTED"); assert n_det == 58, n_det
(FIX / "whitelist_quick.log").write_text(assemble(
    net_block(MTS, False), dns_block(), wl_dom, None, wl_tcp, [],
    ok_dns + [("Домены", "36/36 HTTP  33/36 TLS1.2  33/36 TLS1.3"), ("TCP 16-20KB", "√ 52/110 OK  × 58 блок.  (47% ОК)")]), encoding="utf-8")

(FIX / "dns_hijack_quick.log").write_text(assemble(
    net_block(MTS, False), dns_block(hijack=True), wl_dom, None, tcp_rows(), [],
    [("DNS доступность", "20/36 DoH  12/33 DoT  35/37 UDP"), ("Подмена резолвера", "Google, Cloudflare, Quad9"), ("Подмена ответов", "у 30/35 UDP"),
     ("Домены", "36/36 HTTP  33/36 TLS1.2  33/36 TLS1.3"), ("TCP 16-20KB", "√ 110/110 OK  (100% ОК)")]), encoding="utf-8")

dead_net = list(net_block("…", False))
dead_net[1] = panel_line(dead_net[1], "IPv4: 152.53.157.179  Subnet: 152.53.156.0/22  TTLB: 752 ms", "IPv4: недоступен")
dead_net[2] = panel_line(dead_net[2], "IPv6: 2a0a:4cc0:c2:7cfe:8811:4fff:fee0:20b5", "IPv6: недоступен")
dead_net[3] = panel_line(dead_net[3], "Subnet: 2a0a:4cc0:c0::/43  TTLB: 752 ms", "")
(FIX / "dead_quick.log").write_text(assemble(
    dead_net, dns_block(), dom_rows(all_status="SYN DROP"), None, tcp_rows(all_status="TLS DROP"), [],
    [("DNS доступность", "0/36 DoH  0/33 DoT  0/37 UDP"), ("Подмена резолвера", "—"),
     ("Домены", "0/36 HTTP  0/36 TLS1.2  0/36 TLS1.3"), ("TCP 16-20KB", "√ 0/110 OK  (0% ОК)")]), encoding="utf-8")

(FIX / "crashed_quick.log").write_text("\n".join(real[:200] + ["", "Критическая ошибка: boom", ""]) + "\n", encoding="utf-8")

(FIX / "full_ok.log").write_text(assemble(
    net_block(MTS, False), dns_block(), dom_rows(), None, tcp_rows(), ["Проверка доступности Telegram", ""],
    ok_dns + [("Домены", "36/36 HTTP  36/36 TLS1.2  36/36 TLS1.3"), ("TCP 16-20KB", "√ 110/110 OK  (100% ОК)"),
              ("TG Скачивание", "ОК               ср. 5.2 MB/s, 30.9 MB"),
              ("TG Загрузка", "ЗАМЕДЛЕНИЕ       ср. 0.3 MB/s, 10.0 MB"),
              ("TG Датацентры", "ОК 5/5")]), encoding="utf-8")

sni_lines = TCP_HDR + tcp_table(wl_tcp) + ["",
    "Поиск белых SNI для ASN  Целей: 110 | SNI: 187 | батч: 5", "",
    "  Hetzner AS24940  ✓ yandex.ru #3  vk.com #1",
    "  Cloudflare AS13335  × SNI не найден (все заблокированы)", "",
    "Найдено белых SNI: у 1 из 2 заблокированных AS", ""] + summary_panel([("TCP 16-20KB", "√ 52/110 OK  × 58 блок.  (47% ОК)")]) + [""]
(FIX / "sni_found.log").write_text("\n".join(sni_lines) + "\n", encoding="utf-8")
print("fixtures written")
