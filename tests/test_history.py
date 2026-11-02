import json
from dpiphone.history import find_base, save
from dpiphone.model import RunRecord, RunResult, Verdict


def rec(ts, net="MTS", valid=True, code="ok", mode="quick"):
    return RunRecord(timestamp=ts, mode=mode, net=net, net_raw=net, engine_commit="abc", wrapper_version="0.1.0",
                     result=RunResult(complete=True), verdict=Verdict(code, "t"), valid_base=valid)


def test_save_creates_named_file(tmp_path):
    p = save(tmp_path, rec("2026-11-02T14:32:05"))
    assert p.name == "2026-11-02T14-32-05_quick_MTS.json"
    assert json.loads(p.read_text(encoding="utf-8"))["net"] == "MTS"


def test_find_base_empty(tmp_path):
    assert find_base(tmp_path, "MTS") is None


def test_find_base_picks_latest_valid_on_same_net(tmp_path):
    save(tmp_path, rec("2026-11-02T10:00:00"))
    save(tmp_path, rec("2026-11-02T11:00:00", valid=False, code="vpn"))
    save(tmp_path, rec("2026-11-02T09:00:00"))
    save(tmp_path, rec("2026-11-02T12:00:00", net="Home"))
    base = find_base(tmp_path, "MTS")
    assert base is not None and base.timestamp == "2026-11-02T10:00:00"


def test_find_base_skips_broken_json(tmp_path):
    (tmp_path / "2026-11-02T13-00-00_quick_MTS.json").write_text("{broken", encoding="utf-8")
    save(tmp_path, rec("2026-11-02T10:00:00"))
    assert find_base(tmp_path, "MTS").timestamp == "2026-11-02T10:00:00"


def test_round_trip_record_with_nested_result(tmp_path):
    from dataclasses import asdict
    from dpiphone.model import DomainResult, NetInfo, TcpTarget, record_from_dict
    r = rec("2026-11-02T10:00:00")
    r.result = RunResult(complete=True, net=NetInfo(ipv4="1.2.3.4", ipv6=None, org="Op", asn="AS1", country="RU"),
                         domains=[DomainResult("a.com", "OK", "OK", "OK")], tcp=[TcpTarget("X-1", "AS1", "P", "OK")])
    back = record_from_dict(json.loads(json.dumps(asdict(r))))
    assert back == r and back.result.net.asn == "AS1" and back.result.tcp[0].provider_group == "P"
