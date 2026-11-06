"""extract_entities: deterministic extraction of URLs, phone numbers, amounts, orgs and pressure language."""

from __future__ import annotations

import re

from scamcheck import data
from scamcheck.models import Severity, Signal, Status, ToolResult

# Common TLDs we accept for scheme-less URLs ("maybank2u-verify.com/login"), to avoid matching "e.g".
_TLDS = (
    r"com|net|org|info|biz|xyz|top|icu|cfd|sbs|site|online|live|shop|click|link|vip|app|dev|"
    r"io|co|me|cc|ly|gl|to|my|sg|cn|hk|id|ph|th|vn|in|uk|us"
)
_URL_RE = re.compile(
    r"(?:(?:https?|hxxps?)://[^\s<>\"')]+)"
    r"|(?:\b(?:www\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:"
    + _TLDS
    + r")\b(?:/[^\s<>\"')]*)?)",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_PHONE_RE = re.compile(
    r"(?<![\w/])(?:"
    r"\+?60[\s-]?1\d[\s-]?\d{3,4}[\s-]?\d{4}"  # +60 mobile
    r"|\+?60[\s-]?[3-9][\s-]?\d{3,4}[\s-]?\d{4}"  # +60 landline
    r"|01\d[\s-]?\d{3,4}[\s-]?\d{4}"  # local mobile
    r"|0[3-9][\s-]?\d{3,4}[\s-]?\d{4}"  # local landline
    r"|1[\s-]?[38]00[\s-]?\d{2}[\s-]?\d{4}"  # 1-300 / 1-800
    r"|\+(?!60)\d{1,3}[\s-]?\d{2,4}[\s-]?\d{3,4}[\s-]?\d{3,4}"  # international
    r")(?![\w])"
)
_SHORTCODE_RE = re.compile(r"(?<![\w-])(?:6|3)\d{4}(?![\w-])")
_AMOUNT_RE = re.compile(r"\bRM\s?\d[\d,]*(?:\.\d{1,2})?\b", re.IGNORECASE)

PRESSURE_TERMS: dict[str, list[str]] = {
    "urgency": [
        "urgent",
        "immediately",
        "within 24 hours",
        "within 72 hours",
        "today",
        "now",
        "asap",
        "segera",
        "sekarang",
        "dalam masa 24 jam",
        "hari ini",
    ],
    "threat": [
        "suspended",
        "blocked",
        "locked",
        "permanent",
        "deactivated",
        "legal action",
        "arrest",
        "blacklist",
        "warrant",
        "travel ban",
        "disekat",
        "digantung",
        "dibekukan",
        "tindakan undang-undang",
        "senarai hitam",
        "waran",
        "tangkap",
    ],
    "credential_request": [
        "verify",
        "login",
        "log in",
        "password",
        "tac",
        "otp",
        "pin",
        "update your details",
        "ekyc",
        "sahkan",
        "kata laluan",
        "kemas kini maklumat",
    ],
    "payment_request": [
        "pay",
        "payment",
        "fee",
        "transfer",
        "deposit",
        "processing fee",
        "duty",
        "bayar",
        "yuran",
        "pindahkan",
        "caj",
    ],
    "too_good": [
        "congratulations",
        "won",
        "prize",
        "guaranteed",
        "approved",
        "free",
        "reward",
        "tahniah",
        "menang",
        "hadiah",
        "diluluskan",
        "percuma",
    ],
}


def _refang(text: str) -> str:
    return (
        text.replace("hxxp", "http")
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[dot]", ".")
        .replace("[:]", ":")
    )


def _contains_term(text_lower: str, term: str) -> bool:
    return re.search(r"(?<![\w])" + re.escape(term) + r"(?![\w])", text_lower) is not None


def find_orgs(text: str) -> list[dict[str, str]]:
    lower = text.lower()
    found = []
    for org in data.orgs():
        for alias in org["aliases"]:
            if _contains_term(lower, alias.lower()):
                found.append({"id": org["id"], "name": org["name"], "matched": alias})
                break
    return found


def extract_entities(message: str) -> ToolResult:
    """Extract structured signals from raw message text."""
    text = _refang(message)
    emails = sorted(set(_EMAIL_RE.findall(text)))
    email_domains = {e.split("@", 1)[1].lower() for e in emails}

    urls: list[str] = []
    for m in _URL_RE.findall(text):
        url = m.rstrip(".,;:!?")
        host = re.sub(r"^https?://", "", url, flags=re.I).split("/", 1)[0].lower()
        if host in email_domains:
            continue
        if url not in urls:
            urls.append(url)

    phones = list(dict.fromkeys(p.strip() for p in _PHONE_RE.findall(text)))
    shortcodes = [s for s in _SHORTCODE_RE.findall(text) if not any(s in p for p in phones)]
    amounts = list(dict.fromkeys(_AMOUNT_RE.findall(text)))
    orgs = find_orgs(text)

    lower = text.lower()
    pressure = {
        kind: [t for t in terms if _contains_term(lower, t)]
        for kind, terms in PRESSURE_TERMS.items()
    }
    pressure = {k: v for k, v in pressure.items() if v}

    signals: list[Signal] = []
    if "threat" in pressure and ("urgency" in pressure or "credential_request" in pressure):
        signals.append(
            Signal(
                id="pressure_tactics",
                severity=Severity.AMBER,
                detail="Combines threat language ("
                + ", ".join(pressure["threat"][:3])
                + ") with urgency or a request to verify/log in, a classic pressure pattern.",
            )
        )
    if urls and "credential_request" in pressure:
        signals.append(
            Signal(
                id="link_with_credential_request",
                severity=Severity.AMBER,
                detail="Asks the reader to verify/log in and supplies a link to do it.",
            )
        )
    if orgs and urls and any(o["id"] for o in orgs):
        signals.append(
            Signal(
                id="claims_org_with_link",
                severity=Severity.INFO,
                detail="Claims to be from "
                + ", ".join(o["name"] for o in orgs)
                + " and includes a link; the link domain must be checked against official domains.",
            )
        )

    found_anything = any([urls, phones, emails, amounts, orgs, shortcodes])
    return ToolResult(
        tool="extract_entities",
        status=Status.OK,
        summary=(
            f"{len(urls)} URL(s), {len(phones)} phone number(s), {len(emails)} email(s), "
            f"{len(orgs)} claimed org(s), pressure categories: {', '.join(pressure) or 'none'}"
            if found_anything or pressure
            else "No URLs, phone numbers, organisations or pressure language found."
        ),
        signals=signals,
        evidence={
            "urls": urls,
            "phone_numbers": phones,
            "short_codes": shortcodes,
            "emails": emails,
            "amounts": amounts,
            "claimed_orgs": orgs,
            "pressure_language": pressure,
        },
    )
