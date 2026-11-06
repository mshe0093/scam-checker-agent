"""check_domain: official-domain match, brand impersonation, lookalikes, domain age, Safe Browsing."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from functools import cache
from urllib.parse import urlsplit

import httpx
import tldextract

from scamcheck import data
from scamcheck.config import Settings, get_settings
from scamcheck.models import Severity, Signal, Status, ToolResult
from scamcheck.tools.registration import WhoisQuery, lookup_registration, whois_query

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Heuristics, labelled as such in the output. Free builders host a lot of phishing but also real sites.
FREE_HOSTING_SUFFIXES = (
    "weebly.com",
    "wixsite.com",
    "000webhostapp.com",
    "blogspot.com",
    "pages.dev",
    "web.app",
    "firebaseapp.com",
    "vercel.app",
    "netlify.app",
    "github.io",
    "glitch.me",
    "repl.co",
    "square.site",
    "godaddysites.com",
    "webflow.io",
    "framer.website",
    "ngrok-free.app",
)
HIGH_ABUSE_TLDS = {
    "top",
    "xyz",
    "icu",
    "cfd",
    "sbs",
    "click",
    "link",
    "vip",
    "shop",
    "live",
    "online",
}
SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "s.id",
    "cutt.ly",
    "rb.gy",
    "is.gd",
    "shorturl.at",
    "t.ly",
    "ow.ly",
    "rebrand.ly",
    "linktr.ee",
    "wa.me",
    "goo.su",
    "tiny.cc",
}

_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a", "$": "s"})


@cache
def _extractor() -> tldextract.TLDExtract:
    # suffix_list_urls=() -> use the snapshot bundled with tldextract; never fetch at runtime.
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def host_of(domain_or_url: str) -> str:
    value = domain_or_url.strip()
    if "://" not in value:
        value = "http://" + value
    return (urlsplit(value).hostname or "").rstrip(".").lower()


def registrable(host: str) -> str:
    ext = _extractor()(host)
    return ext.top_domain_under_public_suffix or host


def _fold(label: str) -> str:
    return label.translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w").replace("-", "")


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _official_owner(reg_domain: str) -> dict | None:
    for org in data.orgs():
        if reg_domain in org["official_domains"]:
            return org
    return None


def _find_claimed_org(claimed: str | None) -> dict | None:
    if not claimed:
        return None
    c = claimed.strip().lower()
    for org in data.orgs():
        if c == org["id"] or c in (a.lower() for a in org["aliases"]) or c in org["name"].lower():
            return org
    return None


def _brand_impersonation(host: str) -> dict | None:
    flat = re.sub(r"[^a-z0-9]", "", host)
    for org in data.orgs():
        for token in org["brand_tokens"]:
            if len(token) >= 3 and (token in flat or token in _fold(flat)):
                return org
    return None


def _lookalike(reg_domain: str) -> tuple[dict, str] | None:
    label = reg_domain.split(".", 1)[0]
    folded = _fold(label)
    for org in data.orgs():
        for official in org["official_domains"]:
            off_label = official.split(".", 1)[0]
            if len(off_label) < 5 or label == off_label:
                continue
            if folded == off_label or levenshtein(folded, off_label) <= 2:
                return org, official
    return None


def safe_browsing(url: str, key: str, client: httpx.Client) -> list[str] | None:
    body = {
        "client": {"clientId": "scamcheck", "clientVersion": "0.1"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = client.post(SAFE_BROWSING_URL, params={"key": key}, json=body)
        resp.raise_for_status()
    except httpx.HTTPError:
        return None
    return [m.get("threatType", "UNKNOWN") for m in resp.json().get("matches", [])]


def check_domain(
    domain_or_url: str,
    claimed_org: str | None = None,
    *,
    client: httpx.Client | None = None,
    whois: WhoisQuery = whois_query,
    settings: Settings | None = None,
    now: datetime | None = None,
) -> ToolResult:
    """Assess a domain (or URL) against official domains, lookalikes, registration age and blocklists."""
    settings = settings or get_settings()
    now = now or datetime.now(UTC)
    host = host_of(domain_or_url)
    if not host:
        return ToolResult(
            tool="check_domain",
            status=Status.ERROR,
            summary=f"Could not parse a host from {domain_or_url!r}",
        )

    signals: list[Signal] = []
    evidence: dict = {"host": host}
    sources: list[str] = []
    unverified: list[str] = []

    try:
        ipaddress.ip_address(host)
        signals.append(
            Signal(
                id="ip_literal_host",
                severity=Severity.RED,
                deterministic=True,
                detail=f"Link points to a raw IP address ({host}); legitimate organisations use domain names.",
            )
        )
        return ToolResult(
            tool="check_domain",
            status=Status.OK,
            summary="Raw IP address link.",
            signals=signals,
            evidence=evidence,
        )
    except ValueError:
        pass

    reg = registrable(host)
    evidence["registrable_domain"] = reg
    tld = reg.rsplit(".", 1)[-1]
    claimed = _find_claimed_org(claimed_org)
    owner = _official_owner(reg)

    if owner:
        evidence["official_for"] = owner["name"]
        signals.append(
            Signal(
                id="official_domain",
                severity=Severity.GREEN,
                deterministic=True,
                detail=f"{reg} is a known official domain of {owner['name']}.",
            )
        )
        if claimed and claimed["id"] != owner["id"]:
            signals.append(
                Signal(
                    id="org_domain_mismatch",
                    severity=Severity.AMBER,
                    detail=f"Message claims {claimed['name']} but the link belongs to {owner['name']}.",
                )
            )
    else:
        if claimed:
            detail = (
                f"Message claims to be {claimed['name']} but {reg} is not one of its official "
                f"domains ({', '.join(claimed['official_domains'])})."
            )
            hard = claimed["type"] == "government" and not reg.endswith(".gov.my")
            if hard:
                detail += " Malaysian government sites use .gov.my."
            signals.append(
                Signal(
                    id="claimed_org_domain_mismatch",
                    severity=Severity.RED,
                    deterministic=True,
                    detail=detail,
                )
            )
        if host in SHORTENERS or reg in SHORTENERS:
            signals.append(
                Signal(
                    id="url_shortener",
                    severity=Severity.AMBER,
                    detail=f"{reg} is a link shortener that hides the real destination; resolve it first.",
                )
            )
        else:
            brand = _brand_impersonation(host)
            if brand:
                signals.append(
                    Signal(
                        id="brand_impersonation",
                        severity=Severity.RED,
                        deterministic=True,
                        detail=f"Domain contains the brand name of {brand['name']} but is not an official "
                        f"{brand['name']} domain ({', '.join(brand['official_domains'])}).",
                    )
                )
            else:
                look = _lookalike(reg)
                if look:
                    signals.append(
                        Signal(
                            id="lookalike_domain",
                            severity=Severity.RED,
                            deterministic=True,
                            detail=f"{reg} looks like {look[1]} ({look[0]['name']}) with a few characters "
                            "changed, a typosquatting pattern.",
                        )
                    )
        if any(host == s or host.endswith("." + s) for s in FREE_HOSTING_SUFFIXES):
            signals.append(
                Signal(
                    id="free_hosting",
                    severity=Severity.AMBER,
                    detail=f"Hosted on a free site builder ({host}); banks and agencies don't use these.",
                )
            )
        if tld in HIGH_ABUSE_TLDS:
            signals.append(
                Signal(
                    id="high_abuse_tld",
                    severity=Severity.AMBER,
                    detail=f".{tld} is a cheap TLD heavily used in phishing (heuristic, not proof).",
                )
            )

    own_client = client is None
    client = client or httpx.Client(
        timeout=settings.http_timeout, headers={"User-Agent": settings.user_agent}
    )
    try:
        if not owner:  # age matters for unknown domains; skip the network for known-official ones
            registration = lookup_registration(reg, client, whois)
            evidence["registration_source"] = registration.source
            if registration.registrant_org:
                evidence["registrant_org"] = registration.registrant_org
            if registration.created:
                age_days = (now - registration.created).days
                evidence["created"] = registration.created.date().isoformat()
                evidence["age_days"] = age_days
                sources.append(f"{registration.source} lookup for {reg}")
                if age_days < 30:
                    signals.append(
                        Signal(
                            id="very_new_domain",
                            severity=Severity.RED,
                            deterministic=True,
                            detail=f"{reg} was registered {age_days} day(s) ago ({evidence['created']}).",
                        )
                    )
                elif age_days < 180:
                    signals.append(
                        Signal(
                            id="new_domain",
                            severity=Severity.AMBER,
                            detail=f"{reg} is only {age_days} days old ({evidence['created']}).",
                        )
                    )
                else:
                    signals.append(
                        Signal(
                            id="domain_age",
                            severity=Severity.INFO,
                            detail=f"{reg} was registered on {evidence['created']} ({age_days} days ago). "
                            "Age alone does not make a domain safe.",
                        )
                    )
            elif registration.registered is False:
                evidence["registered"] = False
                signals.append(
                    Signal(
                        id="unregistered_domain",
                        severity=Severity.AMBER,
                        detail=f"The registry says {reg} is not registered right now: the site was "
                        "taken down, expired, or never existed. Common for short-lived phishing "
                        "domains, but not proof by itself.",
                    )
                )
            else:
                unverified.append(f"registration date ({registration.note or 'no data'})")

        if settings.safe_browsing_key:
            url = domain_or_url if "://" in domain_or_url else f"http://{domain_or_url}"
            threats = safe_browsing(url, settings.safe_browsing_key, client)
            if threats is None:
                unverified.append("Google Safe Browsing (request failed)")
            elif threats:
                evidence["safe_browsing"] = threats
                signals.append(
                    Signal(
                        id="safe_browsing_hit",
                        severity=Severity.RED,
                        deterministic=True,
                        detail=f"Google Safe Browsing lists this URL as {', '.join(threats)}.",
                    )
                )
            else:
                evidence["safe_browsing"] = []
                signals.append(
                    Signal(
                        id="safe_browsing_clean",
                        severity=Severity.INFO,
                        detail="Not on Google Safe Browsing lists (new phishing sites often aren't yet).",
                    )
                )
            sources.append("Google Safe Browsing v4")
        else:
            unverified.append("Google Safe Browsing (no API key configured)")
    finally:
        if own_client:
            client.close()

    if unverified:
        evidence["could_not_verify"] = unverified
    reds = [s for s in signals if s.severity is Severity.RED]
    summary = (
        f"{reg}: "
        + (
            "; ".join(s.id for s in reds)
            if reds
            else "official domain"
            if owner
            else "no hard red flags"
        )
        + (f" (could not verify: {', '.join(unverified)})" if unverified else "")
    )
    return ToolResult(
        tool="check_domain",
        status=Status.OK,
        summary=summary,
        signals=signals,
        evidence=evidence,
        sources=sources,
    )
