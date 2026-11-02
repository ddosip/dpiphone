"""Сравнение прогона с базой: что появилось и что исчезло."""

from __future__ import annotations

from dpiphone.model import Diff, RunRecord, RunResult
from dpiphone.verdict import blocked_domains, detected_providers, dns_substituted


def compare(run: RunResult, base: RunRecord) -> Diff:
    b = base.result
    dns_now, dns_before = dns_substituted(run), dns_substituted(b)
    dns_changed = None
    if dns_now and not dns_before:
        dns_changed = "появилась"
    elif dns_before and not dns_now:
        dns_changed = "исчезла"
    dom_now, dom_before = blocked_domains(run), blocked_domains(b)
    prov_now, prov_before = detected_providers(run), detected_providers(b)
    return Diff(
        base_timestamp=base.timestamp,
        dns_changed=dns_changed,
        domains_added=sorted(dom_now - dom_before),
        domains_removed=sorted(dom_before - dom_now),
        providers_added=sorted(prov_now - prov_before),
        providers_removed=sorted(prov_before - prov_now),
    )
