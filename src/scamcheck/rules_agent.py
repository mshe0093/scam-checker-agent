"""RulesAgent: the same tools and event stream as ScamCheckAgent, with fixed rules instead of Claude.

Used for the eval baseline, and as an offline engine so the API and UI run without an API key.
Its verdicts say they come from the rules engine; they are never presented as the AI agent's.

How a verdict is reached (weights and thresholds live in data/rules.json):

1. Every red/amber signal adds risk points, every green signal adds trust points.
2. A deterministic red signal (a fake bank domain, a request for your TAC, an .apk file) gives
   `likely_scam` outright. So does any red signal combined with strong pressure language, or a
   net risk above `likely_scam_net_risk`.
3. Otherwise net risk above `suspicious_net_risk` gives `suspicious`.
4. A message is only cleared as `likely_legitimate` when trust outweighs risk, or when a link or
   phone number was actually checked and nothing was wrong. Naming an organisation is not evidence.
5. Caps in rules.json (for example an unresolved short link) can still block `likely_legitimate`.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from scamcheck import data
from scamcheck.models import Severity, Signal, ToolResult
from scamcheck.registry import CATEGORIES, run_tool
from scamcheck.share import with_share
from scamcheck.tools import tactics

Event = dict[str, Any]

_OUTCOME = {Severity.RED: "fail", Severity.AMBER: "warn", Severity.GREEN: "pass"}


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

        self.verdict = with_share(decide(ent, self.results), self.results)
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


_VERDICT_LEAD = {
    "likely_scam": "Likely scam",
    "suspicious": "Warning signs",
    "likely_legitimate": "Nothing suspicious found",
}
_BASE_ACTIONS = {
    "likely_scam": [
        "Don't click any link, reply, or call any number in the message.",
        "If you already paid or shared details, call your bank's fraud line and NSRC on 997 straight "
        "away. Acting in the first hour gives the best chance of stopping the transfer.",
    ],
    "suspicious": [
        "Don't use the links or numbers in the message. Contact the organisation through its "
        "official app, or a number or website you find yourself.",
    ],
    "likely_legitimate": [
        "The checks found nothing wrong, but if in doubt use the official app or hotline instead "
        "of the message.",
    ],
    "insufficient_information": [
        "If the sender asks for money, codes or personal details, confirm who they are another "
        "way first.",
    ],
}


def _rank(s: Signal) -> tuple[int, int]:
    """Deterministic reds first, then reds, ambers and greens, heaviest first within each."""
    order = {Severity.RED: 1, Severity.AMBER: 2, Severity.GREEN: 3, Severity.INFO: 4}
    return (order[s.severity] - (1 if s.deterministic else 0), -weight(s.id, s.severity))


def _short_org(ent: dict[str, Any]) -> str:
    """'Maybank (Malayan Banking Berhad)' -> 'Maybank', for readable headlines."""
    if not ent["claimed_orgs"]:
        return "the organisation"
    return re.sub(r"\s*\(.*?\)", "", ent["claimed_orgs"][0]["name"]).strip()


def _reason(s: Signal, org: str = "the organisation") -> str:
    t = tactics.by_id(s.id)
    if t:
        return t.reason
    text = data.explanations()["reasons"].get(s.id, s.id.replace("_", " "))
    return text.replace(
        "{org}'s", f"{org}'s" if org != "the organisation" else "the organisation's"
    )


def _kind(s: Signal) -> str:
    """Signals that say the same thing share a kind, so a headline doesn't repeat itself."""
    t = tactics.by_id(s.id)
    if t and t.category != "other":
        return t.category
    for group, ids in data.explanations()["reason_groups"].items():
        if s.id in ids:
            return group
    return s.id


def _check_name(s: Signal) -> str:
    t = tactics.by_id(s.id)
    return t.title if t else s.id.replace("_", " ").capitalize()


def _join(parts: list[str]) -> str:
    return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]


def _category(verdict: str, ranked: list[Signal], results: list[ToolResult]) -> str:
    if verdict in {"likely_legitimate", "insufficient_information"}:
        return "none"
    for s in ranked:
        t = tactics.by_id(s.id)
        if t and t.category in CATEGORIES and t.category != "other":
            return t.category
    patterns = next((r for r in results if r.tool == "match_scam_pattern"), None)
    if patterns and patterns.evidence.get("matches"):
        best = patterns.evidence["matches"][0]
        if best["score"] >= 0.25 and best["category"] in CATEGORIES:
            return best["category"]
    contact = next((r for r in results if r.tool == "lookup_official_contact"), None)
    if contact and contact.evidence.get("type"):
        mapped = data.explanations()["org_type_category"].get(contact.evidence["type"])
        if mapped:
            return mapped
    return "other"


def _official_line(results: list[ToolResult]) -> str | None:
    """How to reach the claimed organisation, taken only from the curated dataset."""
    contact = next((r for r in results if r.tool == "lookup_official_contact"), None)
    if not contact or not contact.evidence.get("org"):
        return None
    org = contact.evidence["org"]
    for c in contact.evidence.get("contacts", []):
        if c["verification"] not in {"official_page", "secondary_source"}:
            continue
        if c["value"].startswith("https://"):
            return f"Check with {org} yourself: {c['label']}, {c['value']}."
        return (
            f"Contact {org} yourself: {c['label']}, {c['value']}. "
            "Don't use any number given in the message."
        )
    domains = contact.evidence.get("official_domains") or []
    if domains:
        return f"{org}'s official website is {domains[0]}. Type it in yourself instead of using a link."
    return None


def decide(ent: dict[str, Any], results: list[ToolResult]) -> dict[str, Any]:
    signals = [s for r in results for s in r.signals if s.severity is not Severity.INFO]
    ranked = sorted(signals, key=_rank)
    hard = [s for s in ranked if s.severity is Severity.RED and s.deterministic]
    reds = [s for s in ranked if s.severity is Severity.RED]
    risky = [s for s in ranked if s.severity in {Severity.RED, Severity.AMBER}]
    greens = [s for s in ranked if s.severity is Severity.GREEN]
    pressure = bool(ent.get("strong_pressure", ent["pressure_language"]))
    # Something was actually checked: a link or a phone number. Naming an organisation is a claim,
    # not evidence, so on its own it can't make a message look legitimate.
    verified = bool(ent["urls"] or ent["phone_numbers"])
    risk = sum(weight(s.id, s.severity) for s in risky)
    trust = sum(weight(s.id, s.severity) for s in greens)
    net = risk - trust
    th = data.rules()["thresholds"]

    if hard or (reds and pressure) or net >= th["likely_scam_net_risk"]:
        verdict, confidence = "likely_scam", "high" if hard else "medium"
    elif net >= th["suspicious_net_risk"]:
        verdict, confidence = "suspicious", "medium"
    elif (greens and net <= 0) or (verified and risk == 0):
        verdict, confidence = "likely_legitimate", "low"
    elif risk < th["min_risk_to_warn"]:
        # One weak hint (a loose template resemblance, a cheap TLD) isn't enough to warn about.
        verdict, confidence = "insufficient_information", "low"
    else:
        verdict, confidence = "suspicious", "low"
    capped = never_legitimate(results)
    if verdict == "likely_legitimate" and capped:
        verdict, confidence = "suspicious", "low"

    # Headline: the verdict plus its two strongest reasons, in plain words.
    org = _short_org(ent)
    if verdict == "insufficient_information":
        if ent["claimed_orgs"]:
            headline = f"It names {org}, but there's no link or phone number to check, and no warning signs."
        else:
            headline = "There's nothing in this message to check: no links, phone numbers or warning signs."
    else:
        pool = greens if verdict == "likely_legitimate" else risky
        reasons: list[str] = []
        kinds: set[str] = set()
        for s in pool:
            if _kind(s) not in kinds:
                kinds.add(_kind(s))
                reasons.append(_reason(s, org))
        reasons = reasons[:2]
        headline = _VERDICT_LEAD[verdict] + (": " + _join(reasons) if reasons else "") + "."

    findings = [
        {"check": _check_name(s), "outcome": _OUTCOME[s.severity], "detail": s.detail}
        for s in ranked
    ]
    for r in results:
        for item in r.evidence.get("could_not_verify", []):
            findings.append({"check": "Not verified", "outcome": "unverified", "detail": item})
    for reason in capped:
        findings.append({"check": "Cannot clear", "outcome": "warn", "detail": reason})

    category = _category(verdict, ranked, results)
    actions: list[str] = []
    if verdict in {"likely_scam", "suspicious"}:
        # One piece of advice per kind of scam, strongest tactic first, at most three.
        seen: set[str] = set()
        for s in risky:
            t = tactics.by_id(s.id)
            if t and _kind(s) not in seen:
                seen.add(_kind(s))
                actions.append(t.advice)
        actions = actions[:3]
        if not actions:
            advice = data.explanations()["category_advice"].get(category)
            if advice:
                actions.append(advice)
        official = _official_line(results)
        if official:
            actions.append(official)
    base = list(_BASE_ACTIONS[verdict])
    if verdict == "likely_scam" and not ent["urls"]:
        base[0] = "Don't reply, send money or share any details."
    actions.extend(base)

    return {
        "verdict": verdict,
        "confidence": confidence,
        "category": category,
        "headline": headline + " (rules engine, no AI)",
        "findings": findings,
        "recommended_actions": actions,
        "engine": "rules",
        "score": {"risk": risk, "trust": trust, "net": net},
    }
