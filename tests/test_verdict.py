from dpiphone.model import DnsResult, DomainResult, NetInfo, RunResult, TcpTarget, TelegramResult
from dpiphone.verdict import decide


def make_run(tcp_statuses=None, tcp=None, domain_statuses=None, fakeip=False, asn="AS8359",
             complete=True, dns_subst=0, telegram=None):
    if tcp is None:
        statuses = tcp_statuses if tcp_statuses is not None else ["OK"] * 110
        tcp = [("X-%d" % i, "Other", st) for i, st in enumerate(statuses)]
    targets = [TcpTarget(id=i, asn="AS1", provider=p, status=s) for i, p, s in tcp]
    if domain_statuses is None:
        domain_statuses = ["OK"] * 36
    if isinstance(domain_statuses, dict):
        items = list(domain_statuses.items())
    else:
        items = [("d%d.com" % i, st) for i, st in enumerate(domain_statuses)]
    domains = [DomainResult(domain=n, http=s, tls12=s, tls13=s) for n, s in items]
    net = NetInfo(ipv4="1.2.3.4", ipv6=None, org="Op", asn=asn, country="RU",
                  fakeip_system_dns=fakeip)
    tg = TelegramResult(*telegram) if telegram else None
    return RunResult(complete=complete, net=net, dns=DnsResult(udp_ok=35, udp_total=37, subst_sub=dns_subst, subst_total=35),
                     domains=domains, fakeip_domains=36 if fakeip else 0, tcp=targets, telegram=tg)


def test_incomplete_is_no_data():
    assert decide(make_run(complete=False), None).code == "no_data"


def test_all_drops_without_rst_is_no_data():
    r = make_run(tcp_statuses=["TLS DROP"] * 110, domain_statuses=["SYN DROP"] * 36)
    assert decide(r, None).code == "no_data"


def test_fakeip_is_vpn():
    assert decide(make_run(fakeip=True), None).code == "vpn"


def test_asn_change_against_base_is_vpn():
    assert decide(make_run(asn="AS197540"), make_run(asn="AS8359")).code == "vpn"


def test_whitelist_requires_three_full_providers():
    r = make_run(tcp=[("HE-01", "Hetzner", "DETECTED")] * 30 + [("CF-01", "Cloudflare", "DETECTED")] * 30
                     + [("X-01", "Other", "OK")] * 50)
    assert decide(r, None).code != "whitelist"
    r2 = make_run(tcp=[("HE-01", "Hetzner", "DETECTED")] * 20 + [("CF-01", "Cloudflare", "DETECTED")] * 20
                      + [("AWS-01", "AWS", "DETECTED")] * 20 + [("X-01", "Other", "OK")] * 50)
    v = decide(r2, None)
    assert v.code == "whitelist" and "Hetzner" in v.text and "Other" in v.text


def test_mixed_provider_does_not_count():
    r = make_run(tcp=[("HE-01", "Hetzner", "DETECTED")] * 19 + [("HE-20", "Hetzner", "OK")]
                     + [("CF-01", "Cloudflare", "DETECTED")] * 20 + [("AWS-01", "AWS", "DETECTED")] * 20
                     + [("X-01", "Other", "OK")] * 50)
    assert decide(r, None).code != "whitelist"


def test_dns_new_only_against_base():
    assert decide(make_run(dns_subst=30), None).code == "ok"
    assert decide(make_run(dns_subst=30), make_run(dns_subst=0)).code == "dns_new"
    assert decide(make_run(dns_subst=30), make_run(dns_subst=30)).code == "ok"


def test_new_blocks_needs_three_more():
    base = make_run(domain_statuses={"a.com": "TLS RST"})
    assert decide(make_run(domain_statuses={"a.com": "TLS RST", "b.com": "TLS RST", "c.com": "TLS RST"}), base).code == "ok"
    v = decide(make_run(domain_statuses={"a.com": "TLS RST", "b.com": "TLS RST", "c.com": "TLS RST", "d.com": "TLS RST"}), base)
    assert v.code == "new_blocks" and "b.com" in v.text and "a.com" not in v.text


def test_channel_by_share_and_telegram():
    assert decide(make_run(domain_statuses=["TLS DROP"] * 10 + ["OK"] * 26, tcp_statuses=["OK"] * 110), None).code == "ok"
    assert decide(make_run(domain_statuses=["TLS DROP"] * 36, tcp_statuses=["OK"] * 70), None).code == "channel"   # 36/106 > 0.25
    assert decide(make_run(telegram=("ОК", "ЗАМЕДЛЕНИЕ", 5, 5)), None).code == "channel"


def test_everything_fine():
    assert decide(make_run(), None).code == "ok"


def test_sni_mode_only_whitelist_or_ok():
    r = RunResult(complete=True, tcp=[TcpTarget(id="X", asn="AS1", provider="Other", status="OK")] * 110)
    assert decide(r, None, mode="sni").code == "ok"
    assert decide(RunResult(complete=False), None, mode="sni").code == "no_data"
