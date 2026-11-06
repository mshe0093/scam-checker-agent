"""Evaluation harness: run the agent (or a rules-only baseline) over a labelled message set.

The baseline uses the same tools with fixed if/else rules and no LLM. It shows what the agent's
judgement adds on top of the tools, and it runs without an API key.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from scamcheck.models import Severity, ToolResult
from scamcheck.registry import run_tool

VERDICTS = ["likely_scam", "suspicious", "likely_legitimate", "insufficient_information"]
# USD per million tokens (input, output) as listed on 2026-10-06. Thinking is billed as output.
PRICES = {
    "claude-opus-5-5": (4.00, 20.00),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-haiku-5-5": (0.10, 0.50),
}


def load_dataset(path: str | Path) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


# ---- rules-only baseline ------------------------------------------------------------------
def baseline_verdict(message: str) -> tuple[dict[str, Any], int]:
    results: list[ToolResult] = []

    def call(name: str, **args: Any) -> ToolResult:
        res = run_tool(name, args)
        results.append(res)
        return res

    ent = call("extract_entities", message=message).evidence
    claimed = ent["claimed_orgs"][0]["name"] if ent["claimed_orgs"] else ""
    for url in ent["urls"]:
        redirect = call("resolve_url_redirects", url=url)
        call("check_domain", domain_or_url=url, claimed_org=claimed)
        final = redirect.evidence.get("final_url")
        if final and redirect.evidence.get("final_domain") not in url:
            call("check_domain", domain_or_url=final, claimed_org=claimed)
    for number in ent["phone_numbers"]:
        call("check_phone_number", number=number)
    call("match_scam_pattern", message=message)

    signals = [s for r in results for s in r.signals]
    hard = any(s.severity is Severity.RED and s.deterministic for s in signals)
    reds = sum(s.severity is Severity.RED for s in signals)
    ambers = sum(s.severity is Severity.AMBER for s in signals)
    greens = sum(s.severity is Severity.GREEN for s in signals)
    pressure = bool(ent["pressure_language"])
    anything = any(ent[k] for k in ("urls", "phone_numbers", "claimed_orgs", "emails"))

    if hard or (reds and pressure):
        verdict = "likely_scam"
    elif reds or ambers >= 2:
        verdict = "suspicious"
    elif greens or (anything and not ambers):
        verdict = "likely_legitimate"
    elif not anything and not pressure:
        verdict = "insufficient_information"
    else:
        verdict = "suspicious"
    return {"verdict": verdict}, len(results)


# ---- runners ------------------------------------------------------------------------------
def run_case(
    case: dict[str, Any], mode: str, agent_factory: Callable[[], Any] | None
) -> dict[str, Any]:
    start = time.monotonic()
    row: dict[str, Any] = {k: case[k] for k in ("id", "label", "category", "notes")}
    try:
        if mode == "baseline":
            verdict, calls = baseline_verdict(case["message"])
            row.update(verdict=verdict["verdict"], tool_calls=calls)
        else:
            agent = agent_factory() if agent_factory else None
            if agent is None:
                raise ValueError("agent mode needs an agent factory")
            events = list(agent.check(case["message"]))
            v = next((e["verdict"] for e in events if e["type"] == "verdict"), None)
            errors = [e["message"] for e in events if e["type"] == "error"]
            row.update(
                verdict=v["verdict"] if v else "error",
                floor_applied=bool(v and v.get("floor_applied")),
                tool_calls=agent.usage["tool_calls"],
                input_tokens=agent.usage["input_tokens"],
                output_tokens=agent.usage["output_tokens"],
                errors=errors,
            )
    except Exception as exc:  # one broken case must not sink the whole run
        row.update(verdict="error", errors=[f"{type(exc).__name__}: {exc}"])
    row["seconds"] = round(time.monotonic() - start, 1)
    return row


def run_eval(
    cases: list[dict[str, Any]],
    mode: str = "agent",
    agent_factory: Callable[[], Any] | None = None,
    workers: int = 4,
    on_row: Callable[[dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    def one(case: dict[str, Any]) -> dict[str, Any]:
        row = run_case(case, mode, agent_factory)
        if on_row:
            on_row(row)
        return row

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(one, cases))


# ---- metrics ------------------------------------------------------------------------------
def _rate(num: int, den: int) -> float | None:
    return round(num / den, 3) if den else None


def score(rows: list[dict[str, Any]], model: str | None = None) -> dict[str, Any]:
    scams = [r for r in rows if r["label"] == "scam"]
    legits = [r for r in rows if r["label"] == "legit"]
    confusion = {
        label: dict(Counter(r["verdict"] for r in rows if r["label"] == label))
        for label in ("scam", "legit")
    }
    flagged = {"likely_scam", "suspicious"}
    metrics: dict[str, Any] = {
        "n": len(rows),
        "scams": len(scams),
        "legit": len(legits),
        # Of the scams, how many did we warn about (likely_scam or suspicious)?
        "scam_detection_rate": _rate(sum(r["verdict"] in flagged for r in scams), len(scams)),
        # The dangerous error: a scam called 'likely_legitimate'.
        "false_legitimate_rate": _rate(
            sum(r["verdict"] == "likely_legitimate" for r in scams), len(scams)
        ),
        # The annoying error: a real message called 'likely_scam'.
        "false_alarm_rate": _rate(sum(r["verdict"] == "likely_scam" for r in legits), len(legits)),
        "legit_cleared_rate": _rate(
            sum(r["verdict"] == "likely_legitimate" for r in legits), len(legits)
        ),
        "abstained": sum(r["verdict"] == "insufficient_information" for r in rows),
        "errors": sum(r["verdict"] == "error" for r in rows),
        "mean_tool_calls": round(sum(r.get("tool_calls", 0) for r in rows) / max(len(rows), 1), 1),
        "floor_applied": sum(bool(r.get("floor_applied")) for r in rows),
        "confusion": confusion,
    }
    tin = sum(r.get("input_tokens", 0) for r in rows)
    tout = sum(r.get("output_tokens", 0) for r in rows)
    if tin or tout:
        metrics["input_tokens"], metrics["output_tokens"] = tin, tout
        if model in PRICES:
            pin, pout = PRICES[model]
            cost = (tin * pin + tout * pout) / 1_000_000
            metrics["est_cost_usd"] = round(cost, 3)
            metrics["est_cost_per_message_usd"] = round(cost / max(len(rows), 1), 4)
    return metrics


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.0f}%"


def to_markdown(metrics: dict[str, Any], rows: list[dict[str, Any]], title: str) -> str:
    lines = [
        f"### {title}",
        "",
        f"{metrics['n']} messages ({metrics['scams']} scam, {metrics['legit']} legitimate)",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Scams flagged (likely scam or suspicious) | **{_pct(metrics['scam_detection_rate'])}** |",
        f"| Scams wrongly called legitimate | **{_pct(metrics['false_legitimate_rate'])}** |",
        f"| Legit messages wrongly called scam | {_pct(metrics['false_alarm_rate'])} |",
        f"| Legit messages cleared as legitimate | {_pct(metrics['legit_cleared_rate'])} |",
        f"| Abstained (not enough information) | {metrics['abstained']} |",
        f"| Errors | {metrics['errors']} |",
        f"| Mean tool calls per message | {metrics['mean_tool_calls']} |",
    ]
    if metrics.get("floor_applied"):
        lines.append(f"| Verdict floor overrides | {metrics['floor_applied']} |")
    if "est_cost_per_message_usd" in metrics:
        lines.append(f"| Est. cost per message | ${metrics['est_cost_per_message_usd']} |")
    lines += [
        "",
        "| Label \\ Verdict | " + " | ".join(VERDICTS) + " | error |",
        "|---|" + "---|" * (len(VERDICTS) + 1),
    ]
    for label in ("scam", "legit"):
        c = metrics["confusion"][label]
        lines.append(
            f"| {label} | " + " | ".join(str(c.get(v, 0)) for v in [*VERDICTS, "error"]) + " |"
        )
    misses = [
        r
        for r in rows
        if (r["label"] == "scam" and r["verdict"] not in {"likely_scam", "suspicious"})
        or (r["label"] == "legit" and r["verdict"] in {"likely_scam", "error"})
    ]
    if misses:
        lines += ["", "Misclassified:", ""]
        lines += [f"- `{r['id']}` ({r['label']}, {r['notes']}) → {r['verdict']}" for r in misses]
    return "\n".join(lines) + "\n"
