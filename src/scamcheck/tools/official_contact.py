"""lookup_official_contact: what a claimed organisation's real channels and policies are."""

from __future__ import annotations

from scamcheck import data
from scamcheck.models import Severity, Signal, Status, ToolResult
from scamcheck.tools.domain import levenshtein


def _match_org(name: str) -> dict | None:
    q = name.strip().lower()
    best, best_score = None, 99
    for org in data.orgs():
        candidates = [org["id"], org["name"].lower(), *(a.lower() for a in org["aliases"])]
        for cand in candidates:
            if q == cand or (len(q) >= 4 and (q in cand or cand in q)):
                return org
            score = levenshtein(q, cand)
            if score < best_score:
                best, best_score = org, score
    return best if best_score <= 2 else None


def lookup_official_contact(org_name: str) -> ToolResult:
    """Return official domains, hotlines and stated policies for a Malaysian organisation."""
    org = _match_org(org_name)
    generic = data.generic_reporting()
    if org is None:
        return ToolResult(
            tool="lookup_official_contact",
            status=Status.UNVERIFIED,
            summary=f"'{org_name}' is not in the curated dataset (a small sample of commonly "
            "impersonated Malaysian organisations). Cannot compare against official channels.",
            evidence={"generic_reporting": generic},
        )
    signals = [
        Signal(
            id="policy",
            severity=Severity.INFO,
            detail=f"{p['text']} [{p['verification']}]",
        )
        for p in org["policies"]
    ]
    sources = sorted(
        {c["source_url"] for c in org["contacts"]} | {p["source_url"] for p in org["policies"]}
    )
    return ToolResult(
        tool="lookup_official_contact",
        status=Status.OK,
        summary=f"{org['name']}: official domains {', '.join(org['official_domains'])}; "
        f"{len(org['contacts'])} verified-or-sourced contact(s).",
        signals=signals,
        evidence={
            "org": org["name"],
            "type": org["type"],
            "official_domains": org["official_domains"],
            "contacts": org["contacts"],
            "generic_reporting": generic,
        },
        sources=sources,
    )
