"""Tool schemas exposed to Claude, and dispatch from tool name to Python function."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from scamcheck.models import Status, ToolResult
from scamcheck.tools import (
    check_domain,
    check_phone_number,
    extract_entities,
    lookup_official_contact,
    match_scam_pattern,
    resolve_url_redirects,
)


def _schema(props: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": props,
        "required": required,
        "additionalProperties": False,
    }


_STR = {"type": "string"}
# Scam categories a verdict can name, shared by the agent's verdict schema and the rules engine.
CATEGORIES = (
    "bank_phishing",
    "parcel_courier",
    "government_impersonation",
    "loan_investment",
    "job_task",
    "prize",
    "impersonation",
    "malware_apk",
    "account_takeover",
    "money_mule",
    "online_shopping",
    "extortion",
    "utility_telco",
)

TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "extract_entities",
        "description": "Deterministically extract URLs, phone numbers, short codes, emails, RM amounts, "
        "claimed Malaysian organisations and pressure language (English + Bahasa Malaysia) from the "
        "suspicious message. Call this first.",
        "input_schema": _schema({"message": _STR}, ["message"]),
    },
    {
        "name": "check_domain",
        "description": "Check a domain or URL: is it an official domain of a known Malaysian org, "
        "does it impersonate a brand or look like a typosquat, how old is its registration (RDAP/"
        "WHOIS), and is it on Google Safe Browsing. Pass the organisation the message claims to be "
        "from as claimed_org (empty string if none).",
        "input_schema": _schema(
            {"domain_or_url": _STR, "claimed_org": _STR}, ["domain_or_url", "claimed_org"]
        ),
    },
    {
        "name": "resolve_url_redirects",
        "description": "Safely follow a link's redirect chain server-side (no rendering, SSRF-guarded) "
        "to find where it really lands. Use for every URL, especially shorteners; then call "
        "check_domain on the final domain if it differs.",
        "input_schema": _schema({"url": _STR}, ["url"]),
    },
    {
        "name": "lookup_official_contact",
        "description": "Look up a Malaysian organisation's official domains, hotlines and stated "
        "policies (e.g. 'never asks for TAC by phone') from a curated, sourced dataset.",
        "input_schema": _schema({"org_name": _STR}, ["org_name"]),
    },
    {
        "name": "match_scam_pattern",
        "description": "Compare the message text with curated Malaysian scam templates (bank phishing, "
        "parcel, LHDN/JPJ/PDRM impersonation, loan/investment, job/task, prize, family impersonation).",
        "input_schema": _schema({"message": _STR}, ["message"]),
    },
    {
        "name": "check_phone_number",
        "description": "Classify a phone number (MY mobile/landline/1-300/international) and compare it "
        "with official hotlines and reported-scam lists.",
        "input_schema": _schema({"number": _STR}, ["number"]),
    },
]

FINDING = _schema(
    {
        "check": _STR,
        "outcome": {"type": "string", "enum": ["fail", "warn", "pass", "unverified"]},
        "detail": _STR,
    },
    ["check", "outcome", "detail"],
)

VERDICT_SPEC: dict[str, Any] = {
    "name": "submit_verdict",
    "description": "Submit the final structured verdict. Call exactly once, after the checks, citing "
    "only what tools actually returned.",
    "input_schema": _schema(
        {
            "verdict": {
                "type": "string",
                "enum": [
                    "likely_scam",
                    "suspicious",
                    "likely_legitimate",
                    "insufficient_information",
                ],
            },
            "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
            "category": {"type": "string", "enum": [*CATEGORIES, "other", "none"]},
            "headline": _STR,
            "findings": {"type": "array", "items": FINDING},
            "recommended_actions": {"type": "array", "items": _STR},
        },
        ["verdict", "confidence", "category", "headline", "findings", "recommended_actions"],
    ),
}


def anthropic_tools() -> list[dict[str, Any]]:
    return [{**spec, "strict": True} for spec in [*TOOL_SPECS, VERDICT_SPEC]]


_DISPATCH: dict[str, Callable[..., ToolResult]] = {
    "extract_entities": lambda message: extract_entities(message),
    "check_domain": lambda domain_or_url, claimed_org="": check_domain(
        domain_or_url, claimed_org or None
    ),
    "resolve_url_redirects": lambda url: resolve_url_redirects(url),
    "lookup_official_contact": lambda org_name: lookup_official_contact(org_name),
    "match_scam_pattern": lambda message: match_scam_pattern(message),
    "check_phone_number": lambda number: check_phone_number(number),
}


def run_tool(name: str, args: dict[str, Any]) -> ToolResult:
    fn = _DISPATCH.get(name)
    if fn is None:
        return ToolResult(tool=name, status=Status.ERROR, summary=f"Unknown tool {name!r}")
    try:
        return fn(**args)
    except Exception as exc:  # a tool failure must never crash the agent; report it honestly
        return ToolResult(
            tool=name, status=Status.ERROR, summary=f"{name} failed: {type(exc).__name__}: {exc}"
        )
