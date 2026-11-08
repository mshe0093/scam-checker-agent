"""Resolve an organisation name (from a message or the model) to an entry in official_orgs.json."""

from __future__ import annotations

import re
from typing import Any

from scamcheck import data
from scamcheck.tools.domain import levenshtein


def _words(text: str, term: str) -> bool:
    return re.search(r"(?<![\w])" + re.escape(term) + r"(?![\w])", text) is not None


def match_org(name: str | None) -> dict[str, Any] | None:
    """Exact id/name/alias first, then whole-word containment (longest wins), then a close spelling.

    Substring matching on its own is unsafe: "sc" (Securities Commission) appears inside "nsrc".
    """
    if not name:
        return None
    q = name.strip().lower()
    orgs = data.orgs()
    cands = [
        (org, c)
        for org in orgs
        for c in {org["id"], org["name"].lower(), *(a.lower() for a in org["aliases"])}
    ]
    for org, c in cands:
        if q == c:
            return org
    best, best_len = None, 0
    for org, c in cands:
        if len(c) >= 3 and _words(q, c) and len(c) > best_len:
            best, best_len = org, len(c)
        elif len(q) >= 4 and _words(c, q) and len(q) > best_len:
            best, best_len = org, len(q)
    if best:
        return best
    close = [(org, levenshtein(q, c)) for org, c in cands if len(c) >= 5 and len(q) >= 5]
    close.sort(key=lambda x: x[1])
    return close[0][0] if close and close[0][1] <= 2 else None
