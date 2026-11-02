from pathlib import Path

from dpiphone.parse import parse_log, load_known_domains

FIX = Path(__file__).parent / "fixtures"
DOMAINS = ["www.instagram.com", "www.facebook.com", "x.com", "www.linkedin.com", "discord.com",
           "gateway.discord.gg", "media.discordapp.net", "www.youtube.com", "soundcloud.com", "meduza.io",
           "www.dw.com", "www.svoboda.org", "holod.media", "www.euronews.com", "www.torproject.org",
           "protonvpn.com", "amnezia.org", "nnmclub.to", "standby-rezka.tv", "hub.docker.com",
           "www.intel.com", "www.canva.com", "www.coursera.org", "aws.amazon.com", "www.apkmirror.com",
           "www.currenttime.tv", "www.messenger.com", "www.themoscowtimes.com", "www.linuxserver.io",
           "danbooru.donmai.us", "browserleaks.com", "www.cdn77.com", "shikimori.io", "kinopub.online",
           "vk.ru", "www.google.com"]


def load(name):
    return parse_log((FIX / name).read_text(encoding="utf-8"), DOMAINS)


def test_mac_vpn_netinfo():
    r = load("mac_vpn_quick.raw.log")
    assert r.complete is True
    assert r.net.ipv4 == "152.53.157.179"
    assert r.net.asn == "AS197540" and "netcup" in r.net.org
    assert r.net.fakeip_system_dns is True
    assert r.fakeip_domains == 36


def test_mac_vpn_dns_summary():
    d = load("mac_vpn_quick.raw.log").dns
    assert (d.doh_ok, d.doh_total, d.dot_ok, d.dot_total, d.udp_ok, d.udp_total) == (36, 36, 32, 33, 35, 37)
    assert d.hijacked_brands == [] and d.hijacked_all is False
    assert (d.subst_sub, d.subst_total) == (7, 35)
    assert d.isp_intercept_warning is True


def test_mac_vpn_domains_and_truncation():
    doms = load("mac_vpn_quick.raw.log").domains
    assert len(doms) == 36
    names = {d.domain for d in doms}
    assert "media.discordapp.net" in names and "www.themoscowtimes.com" in names
    assert all(d.http == "OK" and d.tls12 == "OK" and d.tls13 == "OK" for d in doms)


def test_mac_vpn_tcp_rows_and_continuations():
    tcp = load("mac_vpn_quick.raw.log").tcp
    assert len(tcp) == 110
    by_id = {t.id: t for t in tcp}
    assert by_id["OR-05"].status.startswith("UNKNOWN") and "Protocol error" in by_id["OR-05"].detail
    assert by_id["CNT-05"].status == "TLS RST" and by_id["CNT-05"].asn == "AS141995"
    assert by_id["HE-01"].asn == "AS24940" and by_id["HE-03"].provider_group == "Hetzner"
    assert sum(1 for t in tcp if t.status == "TLS DROP") == 8


def test_console_log_equals_raw_log():
    raw = load("mac_vpn_quick.raw.log")
    con = load("mac_vpn_quick.console.log")
    assert con.complete and len(con.tcp) == 110 and len(con.domains) == 36
    assert con.dns == raw.dns


def test_whitelist_fixture():
    r = load("whitelist_quick.log")
    assert r.net.asn == "AS8359" and r.net.fakeip_system_dns is False
    assert sum(1 for t in r.tcp if t.status == "DETECTED") == 58


def test_crashed_log_is_incomplete():
    r = load("crashed_quick.log")
    assert r.complete is False and r.net is not None and r.tcp is None


def test_full_ok_telegram():
    t = load("full_ok.log").telegram
    assert (t.download, t.upload, t.dc_ok, t.dc_total) == ("ОК", "ЗАМЕДЛЕНИЕ", 5, 5)


def test_sni_found():
    s = load("sni_found.log").sni
    assert (s.found_as, s.blocked_as) == (1, 2)
    assert s.per_provider["Hetzner"] == ["yandex.ru", "vk.com"] and s.per_provider["Cloudflare"] == []


def test_load_known_domains(tmp_path):
    (tmp_path / "domains.txt").write_text("x.com/i/api/1.1/graphql\nwww.google.com\n", encoding="utf-8")
    assert load_known_domains(tmp_path) == ["x.com", "www.google.com"]
