from pathlib import Path

from dpiphone.compare import compare
from dpiphone.model import RunRecord
from dpiphone.netname import file_stem, sanitize
from dpiphone.parse import parse_log
from dpiphone.summary import render
from dpiphone.verdict import decide
from tests.test_parse import DOMAINS

FIX = Path(__file__).parent / "fixtures"


def record(name, mode="quick", base=None):
    run = parse_log((FIX / name).read_text(encoding="utf-8"), DOMAINS)
    v = decide(run, base.result if base else None, mode)
    return RunRecord(timestamp="2026-11-02T14:32:05", mode=mode, net="MTS", net_raw="MTS", engine_commit="8d6d25a",
                     wrapper_version="0.1.0", result=run, verdict=v,
                     base_timestamp=base.timestamp if base else None,
                     diff=compare(run, base) if base else None, valid_base=True)


def test_whitelist_summary_without_base():
    text = render(record("whitelist_quick.log"))
    lines = text.splitlines()
    assert lines[0].startswith("Похоже, включён белый список")
    assert lines[1] == ""
    tcp_line = next(l for l in lines if l.startswith("Хостинги 16–20 КБ: 52/110 OK · обрыв: "))
    assert "Hetzner" in tcp_line and "Cloudflare" in tcp_line
    assert lines[-1] == "Первый прогон на этой сети"


def test_crashed_summary_marks_incomplete():
    text = render(record("crashed_quick.log"))
    assert "Лог неполный" in text and "DNS: не выполнен" in text and "Хостинги 16–20 КБ: не выполнен" in text


def test_summary_with_base_no_changes():
    base = record("whitelist_quick.log")
    base.timestamp = "2026-11-01T19:40:00"
    text = render(record("whitelist_quick.log", base=base))
    assert "Прошлый прогон на MTS (01.11 19:40): без изменений" in text


def test_sni_summary_has_no_net_lines():
    text = render(record("sni_found.log", mode="sni"))
    assert "Сеть:" not in text and "DNS:" not in text
    assert "Белые SNI: найдены для 1 из 2 провайдеров" in text


def test_full_summary_has_telegram_line():
    text = render(record("full_ok.log", mode="full"))
    assert "Telegram: скачивание ОК, загрузка ЗАМЕДЛЕНИЕ, ДЦ 5/5" in text


def test_sanitize():
    assert sanitize("Домашний Wi-Fi 5G") == "Домашний_Wi-Fi_5G"
    assert sanitize("") == "unknown"
    assert sanitize('MTS "Россия"') == "MTS_Россия"
    assert sanitize("x" * 60) == "x" * 40


def test_file_stem():
    assert file_stem("2026-11-02T14:32:05", "quick", "MTS") == "2026-11-02_14-32_quick_MTS"
