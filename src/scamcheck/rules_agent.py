"""RulesAgent: the same tools and event stream as ScamCheckAgent, with fixed rules instead of Claude.

Used for the eval baseline, and as an offline engine so the API and UI run without an API key.
Its verdicts say they come from the rules engine; they are never presented as the AI agent's.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from scamcheck import data
from scamcheck.models import Severity, ToolResult
from scamcheck.registry import run_tool

Event = dict[str, Any]

_OUTCOME = {Severity.RED: "fail", Severity.AMBER: "warn", Severity.GREEN: "pass"}
_CATEGORY_BY_PATTERN = {
    "bank_phishing",
    "parcel_courier",
    "government_impersonation",
    "loan_investment",
    "job_task",
    "prize",
    "impersonation",
}


class RulesAgent:
    engine = "rules"

    def __init__(self) -> None:
        self.results: list[ToolResult] = []
        self.verdict: dict[str, Any] | None = None
        self.usage = {"input_tokens": 0, "output_tokens": 0, "model_calls": 0, "tool_calls": 0}

    def _call(self, name: str, **args: Any) -> Iterator[Event]:
        call_id = f"r{len(self.results) + 1}"
        yield {"type": "tool_call", "id": call_id, "name": name, "input": args}
        res = run_tool(name, args)
        self.results.append(res)
        self.usage["tool_calls"] += 1
        yield {"type": "tool_result", "id": call_id, "name": name, "result": res.model_dump()}

    def check(self, message: str) -> Iterator[Event]:
        self.results, self.verdict = [], None
        yield from self._call("extract_entities", message=message)
        ent = self.results[-1].evidence
        claimed = ent["claimed_orgs"][0]["name"] if ent["claimed_orgs"] else ""
        if claimed:
            yield from self._call("lookup_official_contact", org_name=claimed)
        for url in ent["urls"]:
            yield from self._call("resolve_url_redirects", url=url)
            redirect = self.results[-1]
            yield from self._call("check_domain", domain_or_url=url, claimed_org=claimed)
            final_domain = redirect.evidence.get("final_domain")
            if final_domain and final_domain not in url:
                yield from self._call(
                    "check_domain",
                    domain_or_url=redirect.evidence["final_url"],
                    claimed_org=claimed,
                )
        for number in ent["phone_numbers"]:
            yield from self._call("check_phone_number", number=number)
        yield from self._call("match_scam_pattern", message=message)

        self.verdict = decide(ent, self.results)
        yield {"type": "verdict", "verdict": self.verdict}
        yield {"type": "done", "usage": dict(self.usage)}

    def ask(self, question: str) -> Iterator[Event]:
        yield {
            "type": "text",
            "text": "Follow-up questions need the Claude agent. This server is running the offline "
            "rules engine (no ANTHROPIC_API_KEY configured).",
        }
        yield {"type": "done", "usage": dict(self.usage)}


def weight(signal_id: str, severity: Severity) -> int:
    cfg = data.rules()
    return cfg["weights"].get(signal_id, cfg["default_weights"].get(severity.value, 0))


def never_legitimate(results: list[ToolResult]) -> list[str]:
    """Reasons from data/rules.json caps that forbid a likely_legitimate verdict."""
    ids = {s.id for r in results for s in r.signals}
    return [
        cap["reason"]
        for cap in data.rules()["caps"]["never_legitimate"]
        if cap["when_signal"] in ids and cap.get("unless_signal") not in ids
    ]


def decide(ent: dict[str, Any], results: list[ToolResult]) -> dict[str, Any]:
    signals = [s for r in results for s in r.signals]
    hard = [s for s in signals if s.severity is Severity.RED and s.deterministic]
    reds = [s for s in signals if s.severity is Severity.RED]
    ambers = [s for s in signals if s.severity is Severity.AMBER]
    greens = [s for s in signals if s.severity is Severity.GREEN]
    pressure = bool(ent["pressure_language"])
    anything = any(ent[k] for k in ("urls", "phone_numbers", "claimed_orgs", "emails"))
    risk = sum(weight(s.id, s.severity) for s in [*reds, *ambers])
    trust = sum(weight(s.id, s.severity) for s in greens)
    net = risk - trust
    threshold = data.rules()["thresholds"]["suspicious_net_risk"]

    if hard or (reds and pressure):
        verdict, confidence = "likely_scam", "high" if hard else "medium"
    elif net >= threshold:
        verdict, confidence = "suspicious", "medium"
    elif (greens and net <= 0) or (anything and risk == 0):
        verdict, confidence = "likely_legitimate", "low"
    elif not anything and not pressure and not greens:
        verdict, confidence = "insufficient_information", "low"
    else:
        verdict, confidence = "suspicious", "low"
    capped = never_legitimate(results)
    if verdict == "likely_legitimate" and capped:
        verdict, confidence = "suspicious", "low"

    category = "none"
    patterns = next((r for r in results if r.tool == "match_scam_pattern"), None)
    if patterns and patterns.evidence.get("matches") and verdict != "likely_legitimate":
        best = patterns.evidence["matches"][0]
        if best["score"] >= 0.25 and best["category"] in _CATEGORY_BY_PATTERN:
            category = best["category"]

    findings = [
        {
            "check": s.id.replace("_", " ").capitalize(),
            "outcome": _OUTCOME[s.severity],
            "detail": s.detail,
        }
        for s in [*reds, *ambers, *greens]
    ]
    for r in results:
        for item in r.evidence.get("could_not_verify", []):
            findings.append({"check": "Not verified", "outcome": "unverified", "detail": item})
    for reason in capped:
        findings.append({"check": "Cannot clear", "outcome": "warn", "detail": reason})

    actions = {
        "likely_scam": [
            "Do not click any link or reply.",
            "Never share TAC/OTP codes, PINs or passwords.",
            "If you already paid or shared details, call your bank and NSRC 997 immediately.",
        ],
        "suspicious": [
            "Do not click links in the message. Open the organisation's official app or website yourself.",
            "Verify by calling the organisation's official hotline, not a number in the message.",
        ],
        "likely_legitimate": [
            "The checks found nothing wrong, but if in doubt use the official app or hotline.",
        ],
        "insufficient_information": [
            "There was nothing to check. If the sender asks for money or codes, verify them another way.",
        ],
    }[verdict]
    headlines = {
        "likely_scam": "Strong scam indicators found by the automated checks.",
        "suspicious": "Some warning signs, but nothing decisive.",
        "likely_legitimate": "Nothing in the automated checks points to a scam.",
        "insufficient_information": "No links, numbers or claims to verify.",
    }
    return {
        "verdict": verdict,
        "confidence": confidence,
        "category": category,
        "headline": headlines[verdict] + " (rules engine, no AI)",
        "findings": findings,
        "recommended_actions": actions,
        "engine": "rules",
    }
