import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures"


def run_report(work, mode, net, raw=None):
    engine = work / "engine"
    engine.mkdir(exist_ok=True)
    shutil.copy(ROOT / "tests" / "fixtures" / "mac_vpn_quick.raw.log", work / "unused.log")
    (engine / "domains.txt").write_text("\n".join(l for l in (FIX / "domains_for_tests.txt").read_text().splitlines()), encoding="utf-8")
    (work / "out").mkdir(exist_ok=True)
    if raw:
        shutil.copy(FIX / raw, work / "out" / "raw.log")
    return subprocess.run([sys.executable, str(ROOT / "report.py"), "--mode", mode, "--net", net,
                           "--out", str(work / "out"), "--history", str(work / "history"), "--engine", str(engine)],
                          capture_output=True, text=True, cwd=str(work))


def test_whitelist_run_writes_all_outputs(tmp_path):
    p = run_report(tmp_path, "quick", "MTS", "whitelist_quick.log")
    assert p.returncode == 0, p.stderr
    out = tmp_path / "out"
    assert (out / "summary.txt").exists() and p.stdout.strip() == (out / "summary.txt").read_text(encoding="utf-8").strip()
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}_quick_MTS", (out / "name.txt").read_text(encoding="utf-8").strip())
    rec = json.loads((out / "last.json").read_text(encoding="utf-8"))
    assert rec["verdict"]["code"] == "whitelist" and rec["valid_base"] is True and rec["summary"].startswith("Похоже")
    assert (out / "last.log").read_text(encoding="utf-8").startswith("# DPI Logs")
    assert len(list((tmp_path / "history").glob("*.json"))) == 1


def test_second_run_compares_with_first(tmp_path):
    run_report(tmp_path, "quick", "MTS", "whitelist_quick.log")
    p = run_report(tmp_path, "quick", "MTS", "whitelist_quick.log")
    assert "Прошлый прогон на MTS" in p.stdout and "без изменений" in p.stdout


def test_no_engine_output_is_no_data(tmp_path):
    p = run_report(tmp_path, "quick", "MTS")
    assert p.returncode == 0, p.stderr
    assert p.stdout.splitlines()[0] == "Сеть почти не отвечает, проверить не удалось"
    assert "# НЕПОЛНЫЙ ЛОГ" in (tmp_path / "out" / "last.log").read_text(encoding="utf-8")


def test_console_log_fallback_when_raw_missing(tmp_path):
    (tmp_path / "out").mkdir()
    shutil.copy(FIX / "crashed_quick.log", tmp_path / "out" / "console.log")
    p = run_report(tmp_path, "quick", "MTS")
    assert p.stdout.splitlines()[0] == "Сеть почти не отвечает, проверить не удалось"
    assert "Лог неполный" in p.stdout


def test_network_name_with_spaces_and_cyrillic(tmp_path):
    p = run_report(tmp_path, "quick", "Домашний Wi-Fi 5G", "whitelist_quick.log")
    assert p.returncode == 0, p.stderr
    assert (tmp_path / "out" / "name.txt").read_text(encoding="utf-8").strip().endswith("_quick_Домашний_Wi-Fi_5G")
    assert "Сеть: Домашний Wi-Fi 5G" in p.stdout


def test_stale_raw_log_is_not_reused_after_crash(tmp_path):
    run_report(tmp_path, "quick", "MTS", "whitelist_quick.log")
    assert not (tmp_path / "out" / "raw.log").exists(), "raw.log должен быть переименован после чтения"
    shutil.copy(FIX / "crashed_quick.log", tmp_path / "out" / "console.log")
    p = run_report(tmp_path, "quick", "MTS")
    rec = json.loads((tmp_path / "out" / "last.json").read_text(encoding="utf-8"))
    assert p.stdout.splitlines()[0] == "Сеть почти не отвечает, проверить не удалось"
    assert rec["verdict"]["code"] == "no_data" and rec["valid_base"] is False


def test_name_txt_has_no_trailing_newline(tmp_path):
    run_report(tmp_path, "quick", "MTS", "whitelist_quick.log")
    name = (tmp_path / "out" / "name.txt").read_text(encoding="utf-8")
    assert name == name.strip() and name.endswith("_quick_MTS")


def test_cyrillic_networks_do_not_collapse(tmp_path):
    run_report(tmp_path, "quick", "Дом", "whitelist_quick.log")
    p = run_report(tmp_path, "quick", "Дача", "full_ok.log")
    assert "Первый прогон на этой сети" in p.stdout
    assert (tmp_path / "out" / "name.txt").read_text(encoding="utf-8").endswith("_quick_Дача")


def test_no_comparison_line_on_vpn_or_no_data(tmp_path):
    run_report(tmp_path, "quick", "MTS", "whitelist_quick.log")
    p = run_report(tmp_path, "quick", "MTS", "mac_vpn_quick.raw.log")
    assert "появилось" not in p.stdout and "исчезло" not in p.stdout
    assert "Сравнение пропущено: прогон не полноценный" in p.stdout


def test_asn_change_unsticks_after_repeat(tmp_path):
    # База под VPN без FakeIP (AS197540 из mac-лога без fake-ip), потом честные прогоны на AS8359
    vpn_like = (FIX / "mac_vpn_quick.raw.log").read_text(encoding="utf-8")
    vpn_like = vpn_like.replace("198.18.0.2 (fake-ip)", "192.168.1.1  ").replace("Трафик перехватывается Fake-IP: у 36 доменов", "")
    (FIX / "_tmp_vpn_like.log").write_text(vpn_like, encoding="utf-8")
    try:
        run_report(tmp_path, "quick", "MTS", "_tmp_vpn_like.log")
        p1 = run_report(tmp_path, "quick", "MTS", "full_ok.log")
        p2 = run_report(tmp_path, "quick", "MTS", "full_ok.log")
    finally:
        (FIX / "_tmp_vpn_like.log").unlink()
    assert p1.stdout.splitlines()[0].startswith("Похоже, включён VPN")
    rec = json.loads((tmp_path / "out" / "last.json").read_text(encoding="utf-8"))
    assert rec["verdict"]["code"] != "vpn" and rec["valid_base"] is True, p2.stdout
