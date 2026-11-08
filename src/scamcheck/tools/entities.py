"""extract_entities: deterministic extraction of URLs, phone numbers, amounts, orgs and pressure language."""

from __future__ import annotations

import re

from scamcheck import data
from scamcheck.models import Severity, Signal, Status, ToolResult
from scamcheck.tools import tactics

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
        "before midnight",
        "expires today",
        "last chance",
        "limited slots",
        "segera",
        "sekarang",
        "dalam masa 24 jam",
        "hari ini",
        "tamat hari ini",
        "sebelum tamat",
        "slot terhad",
        "peluang terakhir",
        "cepat",
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
        "dipotong",
        "ditamatkan",
        "dinyahaktifkan",
        "disconnected",
        "terminated",
        "money laundering",
        "pengubahan wang haram",
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
        "username",
        "nama pengguna",
        "bank details",
        "maklumat bank",
        "butiran perbankan",
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
        "bank in",
        "duitnow",
        "modal",
    ],
    "too_good": [
        "congratulations",
        "you won",
        "you have won",
        "prize",
        "guaranteed",
        "approved",
        "reward",
        "lucky draw",
        "tahniah",
        "menang",
        "hadiah",
        "diluluskan",
        "dijamin",
        "cabutan bertuah",
    ],
}
# Words a scam uses that genuine senders also use often. These only count together with a
# stronger tactic, so "see you today" or "pay via the app" alone don't make a message suspicious.
WEAK_TERMS = {"today", "now", "hari ini", "sekarang", "pay", "payment", "bayar", "transfer"}


# Genuine OTP/TAC messages warn the reader to keep the code secret. When these phrases appear,
# "TAC"/"PIN" in the text is the thing being protected, not a request for it.
PROTECTIVE_PHRASES = [
    "never share",
    "do not share",
    "don't share",
    "never disclose",
    "do not disclose",
    "will never ask",
    "never ask",
    "jangan kongsi",
    "jangan dedahkan",
    "jangan berikan",
    "tidak akan meminta",
]
SECRET_TERMS = {"tac", "otp", "pin", "password", "kata laluan"}


def strong_pressure(pressure: dict[str, list[str]]) -> dict[str, list[str]]:
    """Pressure language without the everyday words that genuine messages use too."""
    strong = {k: [t for t in v if t not in WEAK_TERMS] for k, v in pressure.items()}
    return {k: v for k, v in strong.items() if v}


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
    advice = [p for p in PROTECTIVE_PHRASES if _contains_term(lower, p)]
    if advice and "credential_request" in pressure:
        pressure["credential_request"] = [
            t for t in pressure["credential_request"] if t not in SECRET_TERMS
        ]
    pressure = {k: v for k, v in pressure.items() if v}
    hits = tactics.detect(lower, has_url=bool(urls))

    signals: list[Signal] = [tactics.to_signal(h) for h in hits]
    if advice and not urls:
        signals.append(
            Signal(
                id="security_advice",
                severity=Severity.GREEN,
                detail=f"Tells the reader to keep codes secret ('{advice[0]}') and gives no link, "
                "which is how genuine bank OTP/TAC messages are written. Scammers can copy the "
                "wording, so this is weak evidence on its own.",
            )
        )
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
            "strong_pressure": strong_pressure(pressure),
            "security_advice": advice,
            "tactics": hits,
        },
    )
