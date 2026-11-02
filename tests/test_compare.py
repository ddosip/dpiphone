from dpiphone.compare import compare
from dpiphone.model import DnsResult, DomainResult, RunRecord, RunResult, TcpTarget, Verdict


def run(blocked=(), dns_subst=0, detected_providers=()):
    doms = [DomainResult(domain=d, http="OK", tls12="TLS RST" if d in blocked else "OK",
                         tls13="TLS RST" if d in blocked else "OK") for d in ("a.com", "b.com", "c.com", "d.com")]
    tcp = [TcpTarget(id=p + "-1", asn="AS1", provider=p, status="DETECTED" if p in detected_providers else "OK")
           for p in ("Hetzner", "Cloudflare")]
    return RunResult(complete=True, dns=DnsResult(subst_sub=dns_subst, subst_total=35), domains=doms, tcp=tcp)


def record(r):
    return RunRecord(timestamp="2026-11-01T19:40:00", mode="quick", net="MTS", net_raw="MTS", engine_commit="x",
                     wrapper_version="0.1.0", result=r, verdict=Verdict("ok", "t"), valid_base=True)


def test_new_blocked_domains():
    d = compare(run(blocked={"a.com", "b.com", "c.com"}), record(run()))
    assert d.base_timestamp == "2026-11-01T19:40:00"
    assert d.domains_added == ["a.com", "b.com", "c.com"]
    assert d.domains_removed == [] and d.providers_added == [] and d.dns_changed is None


def test_dns_substitution_disappeared():
    d = compare(run(dns_subst=0), record(run(dns_subst=30)))
    assert d.dns_changed == "исчезла"


def test_identical_runs_are_empty():
    d = compare(run(blocked={"a.com"}, detected_providers={"Hetzner"}), record(run(blocked={"a.com"}, detected_providers={"Hetzner"})))
    assert d.is_empty()


def test_provider_added():
    d = compare(run(detected_providers={"Hetzner"}), record(run()))
    assert d.providers_added == ["Hetzner"]
