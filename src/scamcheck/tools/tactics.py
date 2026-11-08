"""Scam-tactic detection: data-driven regex rules from data/tactics.json.

Each tactic describes something scammers ask for or claim (install an .apk, share a code, move money
to a "safe account", rent out a bank account). The rules live in JSON so they can be reviewed and
tuned without touching code, and every tactic carries the plain-language explanation and advice the
rules engine shows to users.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cache
from typing import Any

from scamcheck import data
from scamcheck.models import Severity, Signal

# A match counts as negated when one of these words comes just before it:
# "never share your TAC" or "jangan kongsi kod" is advice, not a request. The window is short so
# that "If this was not you, reply with the TAC" still counts as a request.
_NEGATION = re.compile(
    r"\b(never|do not|don't|dont|no need to|jangan|usah|tidak perlu|tak perlu)\b[^.!?\n]{0,15}$"
)


@dataclass(frozen=True)
class Tactic:
    id: str
    severity: Severity
    deterministic: bool
    category: str
    title: str
    reason: str
    detail: str
    advice: str
    groups: tuple[tuple[re.Pattern[str], ...], ...]
    unless: tuple[re.Pattern[str], ...]
    negatable: bool
    needs_url: bool
    source_url: str | None


@cache
def tactics() -> tuple[Tactic, ...]:
    out = []
    for t in data.tactics():
        out.append(
            Tactic(
                id=t["id"],
                severity=Severity(t["severity"]),
                deterministic=t.get("deterministic", False),
                category=t.get("category", "other"),
                title=t["title"],
                reason=t["reason"],
                detail=t["detail"],
                advice=t["advice"],
                groups=tuple(tuple(re.compile(r) for r in g) for g in t["all"]),
                unless=tuple(re.compile(r) for r in t.get("unless", [])),
                negatable=t.get("negatable", False),
                needs_url=t.get("needs_url", False),
                source_url=t.get("source_url"),
            )
        )
    return tuple(out)


def by_id(tactic_id: str) -> Tactic | None:
    return next((t for t in tactics() if t.id == tactic_id), None)


def _first_match(patterns: tuple[re.Pattern[str], ...], text: str, negatable: bool) -> str | None:
    for pat in patterns:
        for m in pat.finditer(text):
            if negatable and _NEGATION.search(text[max(0, m.start() - 40) : m.start()]):
                continue
            return m.group(0)
    return None


def detect(text_lower: str, has_url: bool) -> list[dict[str, Any]]:
    """Return the tactics found in already lower-cased, refanged text, with the matched phrases."""
    found = []
    for t in tactics():
        if t.needs_url and not has_url:
            continue
        if any(u.search(text_lower) for u in t.unless):
            continue
        matched = []
        for group in t.groups:
            hit = _first_match(group, text_lower, t.negatable)
            if hit is None:
                break
            matched.append(hit.strip())
        else:
            found.append({"id": t.id, "matched": matched})
    return found


def to_signal(hit: dict[str, Any]) -> Signal:
    t = by_id(hit["id"])
    assert t is not None
    quoted = ", ".join(f"'{m}'" for m in dict.fromkeys(hit["matched"]))
    return Signal(
        id=t.id,
        severity=t.severity,
        detail=f"{t.detail} (matched {quoted})",
        deterministic=t.deterministic,
    )
