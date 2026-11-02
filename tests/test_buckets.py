import pytest
from dpiphone.buckets import bucket, normalize


@pytest.mark.parametrize("status,expected", [
    ("TLS RST", "block"), ("DETECTED", "block"), ("BLOCKED", "block"), ("ISP PAGE", "block"),
    ("TLS DROP", "channel"), ("SYN DROP", "channel"), ("READ TIMEOUT", "channel"),
    ("OK", "noise"), ("NO TLS1.3", "noise"), ("DNS FAIL", "noise"), ("UNKNOWN", "noise"),
    ("UNKNOWN RemoteProtocolEr…", "noise"), (" tls rst ", "block"),
])
def test_bucket(status, expected):
    assert bucket(status) == expected


def test_redir_to_foreign_domain_is_block():
    assert bucket("REDIR", "→ blocked.isp.ru") == "block"


def test_redir_same_domain_is_noise():
    assert bucket("REDIR", "301") == "noise"


def test_normalize_strips_tail():
    assert normalize("UNKNOWN RemoteProtocolEr…") == "UNKNOWN"
    assert normalize("TLS RST (dpi)") == "TLS RST"
