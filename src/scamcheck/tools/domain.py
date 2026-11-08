"""check_domain: official-domain match, brand impersonation, lookalikes, domain age, Safe Browsing."""

from __future__ import annotations

import ipaddress
import math
import re
import unicodedata
from datetime import UTC, datetime
from functools import cache
from urllib.parse import urlsplit

import dnstwist
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

# Cyrillic/Greek/Armenian letters that render like Latin ones (a hand-picked subset of Unicode
# TR39 confusables), written as escapes so the source itself has no look-alike characters. Accented Latin letters are handled by stripping combining marks.
_CONFUSABLES = str.maketrans(
    {
        "\u0430": "a",  # cyrillic small letter a
        "\u0432": "b",  # cyrillic small letter ve
        "\u0441": "c",  # cyrillic small letter es
        "\u0501": "d",  # cyrillic small letter komi de
        "\u0435": "e",  # cyrillic small letter ie
        "\u0451": "e",  # cyrillic small letter io
        "\u04bb": "h",  # cyrillic small letter shha
        "\u043d": "h",  # cyrillic small letter en
        "\u0456": "i",  # cyrillic small letter byelorussian-ukrainian i
        "\u0457": "i",  # cyrillic small letter yi
        "\u04cf": "l",  # cyrillic small letter palochka
        "\u0458": "j",  # cyrillic small letter je
        "\u043a": "k",  # cyrillic small letter ka
        "\u043c": "m",  # cyrillic small letter em
        "\u043f": "n",  # cyrillic small letter pe
        "\u043e": "o",  # cyrillic small letter o
        "\u0440": "p",  # cyrillic small letter er
        "\u051b": "q",  # cyrillic small letter qa
        "\u0433": "r",  # cyrillic small letter ghe
        "\u0455": "s",  # cyrillic small letter dze
        "\u0442": "t",  # cyrillic small letter te
        "\u0443": "y",  # cyrillic small letter u
        "\u0445": "x",  # cyrillic small letter ha
        "\u051d": "w",  # cyrillic small letter we
        "\u03b1": "a",  # greek small letter alpha
        "\u03b2": "b",  # greek small letter beta
        "\u03b5": "e",  # greek small letter epsilon
        "\u03b9": "i",  # greek small letter iota
        "\u03ba": "k",  # greek small letter kappa
        "\u03bd": "v",  # greek small letter nu
        "\u03bf": "o",  # greek small letter omicron
        "\u03c1": "p",  # greek small letter rho
        "\u03c4": "t",  # greek small letter tau
        "\u03c5": "u",  # greek small letter upsilon
        "\u03c7": "x",  # greek small letter chi
        "\u03c9": "w",  # greek small letter omega
        "\u0131": "i",  # latin small letter dotless i
        "\u0261": "g",  # latin small letter script g
        "\u0578": "n",  # armenian small letter vo
        "\u057d": "u",  # armenian small letter seh
    }
)

# Words in a URL path that mean "log in / verify" (EN + BM). On an unofficial domain they are a
# classic phishing-kit shape; on official domains they are normal and ignored.
PATH_KEYWORDS = (
    "login", "log-in", "signin", "sign-in", "verify", "verification", "secure", "account",
    "update", "unlock", "confirm", "auth", "otp", "tac", "ekyc", "wallet",
    "sahkan", "pengesahan", "kemaskini", "kemas-kini", "akaun", "log-masuk",
)  # fmt: skip
_PATH_KEYWORD_RE = re.compile(
    r"(?<![a-z])(" + "|".join(re.escape(k) for k in PATH_KEYWORDS) + r")(?![a-z])"
)
ESTABLISHED_DAYS = 3 * 365
_FUZZERS = [
    "addition", "bitsquatting", "hyphenation", "insertion", "omission", "plural",
    "repetition", "replacement", "transposition", "vowel-swap",
]  # fmt: skip


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


def decode_host(host: str) -> str:
    """Punycode (xn--) labels back to Unicode, so lookalike letters can be seen and folded."""
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label[4:].encode("ascii").decode("punycode")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


def skeleton(text: str) -> str:
    """Latin 'skeleton' of a label: other-alphabet lookalikes mapped, accents stripped."""
    text = unicodedata.normalize("NFKD", text.lower().translate(_CONFUSABLES))
    return "".join(c for c in text if not unicodedata.combining(c))


def _fold(label: str) -> str:
    label = skeleton(label)
    return label.translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w").replace("-", "")


def _label(domain: str) -> str:
    """The registrable label without its public suffix: maybank2u.com.my -> maybank2u."""
    ext = _extractor()(domain)
    return ext.domain or domain.split(".", 1)[0]


@cache
def _fuzz_index() -> dict[str, tuple[str, str, str]]:
    """Permutations of every official domain label (dnstwist fuzzers), computed once (~0.2s).

    Maps a permuted label to (org id, official domain, fuzzer). Matched on the label only, so a
    swapped TLD is caught too. Labels under 5 characters are left out: their permutations
    collide with too many unrelated real names.
    """
    official_labels = {_label(d) for org in data.orgs() for d in org["official_domains"]}
    index: dict[str, tuple[str, str, str]] = {}
    for org in data.orgs():
        for official in org["official_domains"]:
            if len(_label(official)) < 5:
                continue
            fuzzer = dnstwist.Fuzzer(official)
            fuzzer.generate(fuzzers=_FUZZERS)
            for perm in fuzzer.permutations():
                label = _label(perm["domain"])
                if label and label not in official_labels:
                    index.setdefault(label, (org["id"], official, perm["fuzzer"]))
    return index


def _org(org_id: str) -> dict:
    return next(o for o in data.orgs() if o["id"] == org_id)


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
    from scamcheck.tools.orgs import match_org

    return match_org(claimed)


def _brand_impersonation(host: str) -> dict | None:
    flat = re.sub(r"[^a-z0-9]", "", skeleton(decode_host(host)))
    for org in data.orgs():
        for token in org["brand_tokens"]:
            if len(token) >= 3 and (token in flat or token in _fold(flat)):
                return org
    return None


def _embedded_official(host: str, reg: str) -> tuple[dict, str] | None:
    """An official domain spelled out in front of another one: maybank2u.com.my.secure-xyz.com."""
    prefix = host[: -len(reg)].rstrip(".") if host.endswith(reg) else ""
    if not prefix:
        return None
    for org in data.orgs():
        for official in org["official_domains"]:
            if (
                prefix == official
                or prefix.endswith("." + official)
                or (official + ".") in prefix + "."
            ):
                return org, official
    return None


def _lookalike(reg_domain: str) -> tuple[dict, str, str] | None:
    """(org, official domain, how) when the label imitates an official one."""
    raw = _label(reg_domain)
    label = skeleton(decode_host(raw))
    folded = _fold(label)
    hit = _fuzz_index().get(label) or _fuzz_index().get(folded)
    if hit:
        return _org(hit[0]), hit[1], f"a '{hit[2]}' permutation"
    for org in data.orgs():
        for official in org["official_domains"]:
            off_label = _label(official)
            if len(off_label) < 5 or raw == off_label:
                continue
            if label == off_label or folded == off_label:
                return org, official, "the same name written with look-alike characters"
            # Two edits only when both names are long enough for that to still look alike.
            max_dist = 2 if min(len(folded), len(off_label)) >= 6 else 1
            if levenshtein(folded, off_label) <= max_dist:
                return org, official, "a few characters changed"
    return None


def _entropy(text: str) -> float:
    counts = {c: text.count(c) for c in set(text)}
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def random_looking(label: str) -> bool:
    """Machine-generated names (xk7q9zt2wpl.com). Conservative: long, little vowel structure."""
    chars = re.sub(r"[^a-z0-9]", "", label)
    if len(chars) < 10:
        return False
    vowels = sum(c in "aeiou" for c in chars)
    run = max((len(m) for m in re.findall(r"[bcdfghjklmnpqrstvwxz0-9]+", chars)), default=0)
    return _entropy(chars) > 3.2 and (vowels / len(chars) < 0.2 or run >= 7)


def path_keywords(url: str) -> list[str]:
    if "://" not in url:
        url = "http://" + url
    parts = urlsplit(url)
    path = (parts.path + "?" + parts.query).lower()
    return list(dict.fromkeys(m.group(1) for m in _PATH_KEYWORD_RE.finditer(path)))


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
    decoded = decode_host(host)
    idn = decoded != host or not host.isascii()
    if idn:
        evidence["unicode_host"] = decoded
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
            alphabet = " It uses letters from another alphabet that look Latin." if idn else ""
            embedded = _embedded_official(host, reg)
            brand = None if embedded else _brand_impersonation(host)
            look = None if (embedded or brand) else _lookalike(reg)
            if embedded:
                signals.append(
                    Signal(
                        id="embedded_official_domain",
                        severity=Severity.RED,
                        deterministic=True,
                        detail=f"The address starts like {embedded[1]} ({embedded[0]['name']}) but "
                        f"actually belongs to {reg}.",
                    )
                )
            elif brand:
                signals.append(
                    Signal(
                        id="brand_impersonation",
                        severity=Severity.RED,
                        deterministic=True,
                        detail=f"Domain contains the brand name of {brand['name']} but is not an official "
                        f"{brand['name']} domain ({', '.join(brand['official_domains'])}).{alphabet}",
                    )
                )
            elif look:
                signals.append(
                    Signal(
                        id="lookalike_domain",
                        severity=Severity.RED,
                        deterministic=True,
                        detail=f"{reg} imitates {look[1]} ({look[0]['name']}): {look[2]}, a "
                        f"typosquatting pattern.{alphabet}",
                    )
                )
            elif idn:
                signals.append(
                    Signal(
                        id="idn_host",
                        severity=Severity.AMBER,
                        detail=f"The address uses non-Latin or accented letters (shown as {decoded}); "
                        "these can disguise one name as another.",
                    )
                )
            keywords = path_keywords(domain_or_url)
            if keywords:
                evidence["path_keywords"] = keywords
                signals.append(
                    Signal(
                        id="phishing_path_keywords",
                        severity=Severity.AMBER,
                        detail=f"The link path contains {', '.join(keywords[:4])} on a domain that is "
                        "not the organisation's, the usual shape of a fake login page.",
                    )
                )
            sub_labels = [x for x in host[: -len(reg)].rstrip(".").split(".") if x and x != "www"]
            if len(sub_labels) >= 3:
                signals.append(
                    Signal(
                        id="excessive_subdomains",
                        severity=Severity.AMBER,
                        detail=f"{host} stacks {len(sub_labels)} subdomains in front of {reg}, often "
                        "done to push the real domain out of view on a phone screen.",
                    )
                )
            if random_looking(_label(reg)):
                signals.append(
                    Signal(
                        id="random_looking_domain",
                        severity=Severity.AMBER,
                        detail=f"{reg} looks machine-generated (random letters), typical of throwaway "
                        "scam domains (heuristic).",
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
                elif (
                    age_days >= ESTABLISHED_DAYS
                    and "path_keywords" not in evidence
                    and not any(s.severity is Severity.RED for s in signals)
                ):
                    signals.append(
                        Signal(
                            id="established_domain",
                            severity=Severity.GREEN,
                            detail=f"{reg} has been registered since {evidence['created']} "
                            f"(about {age_days // 365} years). Throwaway scam domains rarely last "
                            "that long, though old sites can still be hacked.",
                        )
                    )
                else:
                    # An old domain hosting a login-looking path may be a hacked site: its age
                    # says nothing about the page, so no trust is given for it.
                    note = (
                        " Its age is not counted as trust because the link looks like a login "
                        "page placed on it."
                        if "path_keywords" in evidence
                        else " Age alone does not make a domain safe."
                    )
                    signals.append(
                        Signal(
                            id="domain_age",
                            severity=Severity.INFO,
                            detail=f"{reg} was registered on {evidence['created']} "
                            f"({age_days} days ago).{note}",
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
