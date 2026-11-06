"""Domain registration date lookup: RDAP first, then raw WHOIS (port 43) via the IANA referral.

Why both: many ccTLDs, including .my, publish no RDAP service (rdap.org returns 404 and the IANA
RDAP bootstrap has no entry), but MYNIC still answers WHOIS on whois.mynic.my:43.
"""

from __future__ import annotations

import re
import socket
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx

RDAP_URL = "https://rdap.org/domain/{domain}"
IANA_WHOIS = "whois.iana.org"
# Pre-seeded so the common case needs one WHOIS round-trip, not two.
KNOWN_WHOIS = {
    "my": "whois.mynic.my",
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
}

_CREATED_RE = re.compile(
    r"^\s*(?:creation date|created(?: on)?|registered on|registration time|domain registration date|"
    r"registered|domain record activated|record created)\s*[:.]\s*(.+?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_REGISTRANT_ORG_RE = re.compile(r"^\s*registrant organi[sz]ation\s*:\s*(.+?)\s*$", re.I | re.M)
_NOT_FOUND_RE = re.compile(
    r"no match for|not found|no data found|is available for registration|no entries found|"
    r"status:\s*free|domain not found",
    re.IGNORECASE,
)
_REFER_RE = re.compile(r"^\s*(?:refer|whois):\s*(\S+)", re.IGNORECASE | re.MULTILINE)

WhoisQuery = Callable[[str, str], str]


@dataclass
class Registration:
    created: datetime | None
    source: str  # "rdap" | "whois:<server>" | "none"
    registrant_org: str | None = None
    note: str | None = None
    registered: bool | None = None  # False = registry says the name is not registered


def whois_query(server: str, query: str, timeout: float = 8.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(len(c) for c in chunks) > 200_000:
                break
    return b"".join(chunks).decode("utf-8", errors="replace")


def parse_date(raw: str) -> datetime | None:
    raw = raw.strip()
    for candidate in (raw, raw.replace("Z", "+00:00"), raw.split(" ")[0]):
        try:
            dt = datetime.fromisoformat(candidate)
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            pass
    for fmt in ("%d-%b-%Y", "%d/%m/%Y", "%Y.%m.%d", "%d.%m.%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(raw.split(" ")[0], fmt).replace(tzinfo=UTC)
        except ValueError:
            pass
    return None


def from_rdap(domain: str, client: httpx.Client) -> Registration | None:
    try:
        resp = client.get(RDAP_URL.format(domain=domain), follow_redirects=True)
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    try:
        payload = resp.json()
    except ValueError:
        return None
    for event in payload.get("events", []):
        if event.get("eventAction") == "registration" and event.get("eventDate"):
            created = parse_date(event["eventDate"])
            if created:
                return Registration(created=created, source="rdap")
    return None


def from_whois(domain: str, query: WhoisQuery = whois_query) -> Registration | None:
    tld = domain.rsplit(".", 1)[-1].lower()
    server = KNOWN_WHOIS.get(tld)
    if server is None:
        try:
            refer = _REFER_RE.search(query(IANA_WHOIS, tld))
        except OSError:
            return None
        if not refer:
            return None
        server = refer.group(1)
    try:
        text = query(server, domain)
    except OSError:
        return None
    match = _CREATED_RE.search(text)
    org = _REGISTRANT_ORG_RE.search(text)
    registrant = org.group(1) if org and "REDACTED" not in org.group(1).upper() else None
    # Only trust "not found" wording in the first lines; registry footers contain boilerplate.
    if not match and _NOT_FOUND_RE.search("\n".join(text.strip().splitlines()[:5])):
        return Registration(
            created=None,
            source=f"whois:{server}",
            registered=False,
            note="domain is not currently registered (never existed, expired or taken down)",
        )
    if not match:
        return Registration(
            created=None,
            source=f"whois:{server}",
            registrant_org=registrant,
            note="WHOIS answered but published no creation date",
        )
    return Registration(
        created=parse_date(match.group(1)), source=f"whois:{server}", registrant_org=registrant
    )


def lookup_registration(
    domain: str, client: httpx.Client, whois: WhoisQuery = whois_query
) -> Registration:
    reg = from_rdap(domain, client)
    if reg and reg.created:
        return reg
    reg = from_whois(domain, whois)
    if reg:
        return reg
    return Registration(created=None, source="none", note="Neither RDAP nor WHOIS returned data")
