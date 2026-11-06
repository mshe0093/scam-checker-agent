"""check_phone_number: classify a Malaysian number and compare it with official hotlines.

There is no public API for PDRM's Semak Mule, so reputation lookups degrade to 'unverified'
with the manual-check link instead of guessing.
"""

from __future__ import annotations

import re

from scamcheck import data
from scamcheck.models import Severity, Signal, Status, ToolResult

SEMAK_MULE = "https://semakmule.rmp.gov.my"


def normalise(number: str) -> str:
    digits = re.sub(r"[^\d+]", "", number)
    if digits.startswith("+"):
        return digits
    if digits.startswith("60"):
        return "+" + digits
    if digits.startswith("1300") or digits.startswith("1800"):
        return digits  # national toll/shared-cost numbers have no +60 form in practice
    if digits.startswith("0"):
        return "+60" + digits[1:]
    return digits


def classify(e164: str) -> str:
    if e164.startswith(("1300", "1800")):
        return "corporate_1300_1800"
    if re.fullmatch(r"\d{3,5}", e164):
        return "short_code_or_service"
    if e164.startswith("+601"):
        return "my_mobile"
    if e164.startswith("+60"):
        return "my_landline"
    if e164.startswith("+"):
        return "international"
    return "unknown"


def check_phone_number(number: str) -> ToolResult:
    """Classify a phone number and check it against official hotlines and the reported list."""
    e164 = normalise(number)
    kind = classify(e164)
    signals: list[Signal] = []
    evidence: dict = {"input": number, "normalised": e164, "type": kind}

    official_hits = []
    for org in data.orgs():
        for c in org["contacts"]:
            if normalise(c["value"]) == e164:
                official_hits.append({"org": org["name"], **c})
    for g in data.generic_reporting():
        if normalise(g["value"]) == e164:
            official_hits.append({"org": "Government", **g})
    if official_hits:
        evidence["official_match"] = official_hits
        hit = official_hits[0]
        signals.append(
            Signal(
                id="matches_official_number",
                severity=Severity.GREEN,
                detail=f"Matches {hit['org']}'s listed number ({hit['label']}, {hit['verification']}). "
                "Caller ID and SMS sender names CAN be spoofed; PDRM reported a caller-ID-spoofing "
                "syndicate in Jan 2026. If unsure, hang up and call the number yourself.",
            )
        )
    elif kind == "my_mobile":
        signals.append(
            Signal(
                id="personal_mobile",
                severity=Severity.AMBER,
                detail="A personal mobile number. Banks and government agencies contact customers "
                "from official hotlines, not personal mobiles or WhatsApp numbers.",
            )
        )
    elif kind == "international":
        signals.append(
            Signal(
                id="international_number",
                severity=Severity.AMBER,
                detail="An international number claiming to represent a Malaysian organisation is unusual.",
            )
        )

    reported = [r for r in data.reported_numbers() if normalise(r["number"]) == e164]
    if reported:
        evidence["reported"] = reported
        signals.append(
            Signal(
                id="reported_scam_number",
                severity=Severity.RED,
                deterministic=True,
                detail=f"Listed as a reported scam number ({reported[0].get('source_url', 'local list')}).",
            )
        )
    evidence["could_not_verify"] = [
        f"Scam-report databases: PDRM Semak Mule has no public API. Check manually at {SEMAK_MULE}."
    ]
    return ToolResult(
        tool="check_phone_number",
        status=Status.OK if (official_hits or reported) else Status.UNVERIFIED,
        summary=(
            f"{e164} ({kind})"
            + (f": matches official number of {official_hits[0]['org']}" if official_hits else "")
            + ("; reputation not verifiable automatically" if not reported else "; REPORTED")
        ),
        signals=signals,
        evidence=evidence,
        sources=[SEMAK_MULE],
    )
