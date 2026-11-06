"""match_scam_pattern: TF-IDF cosine + indicator hits against curated Malaysian scam templates."""

from __future__ import annotations

import math
import re
from collections import Counter
from functools import cache

from scamcheck import data
from scamcheck.models import Severity, Signal, Status, ToolResult

_TOKEN = re.compile(r"[a-z0-9]+")
_STOP = {
    "the",
    "a",
    "an",
    "to",
    "of",
    "and",
    "or",
    "your",
    "you",
    "is",
    "at",
    "in",
    "on",
    "for",
    "be",
    "has",
    "have",
    "been",
    "it",
    "this",
    "our",
    "we",
    "us",
    "by",
    "with",
    "will",
    "are",
    "anda",
    "di",
    "dan",
    "untuk",
    "kami",
    "ini",
    "telah",
    "yang",
    "dari",
    "sila",
    "akan",
}


def _tokens(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in _STOP and len(t) > 1]


@cache
def _index() -> tuple[list[dict], dict[str, float], list[dict[str, float]]]:
    pats = data.patterns()
    docs = [_tokens(p["template"] + " " + " ".join(p["indicators"])) for p in pats]
    df: Counter[str] = Counter()
    for d in docs:
        df.update(set(d))
    n = len(docs)
    idf = {t: math.log((1 + n) / (1 + c)) + 1 for t, c in df.items()}
    vecs = [_vec(d, idf) for d in docs]
    return pats, idf, vecs


def _vec(tokens: list[str], idf: dict[str, float]) -> dict[str, float]:
    tf = Counter(tokens)
    v = {t: c * idf.get(t, 1.0) for t, c in tf.items()}
    norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
    return {t: x / norm for t, x in v.items()}


def _cos(a: dict[str, float], b: dict[str, float]) -> float:
    if len(a) > len(b):
        a, b = b, a
    return sum(x * b.get(t, 0.0) for t, x in a.items())


def match_scam_pattern(message: str, top_k: int = 3) -> ToolResult:
    """Compare a message against known scam templates; return the closest matches with scores."""
    pats, idf, vecs = _index()
    qv = _vec(_tokens(message), idf)
    lower = message.lower()
    scored = []
    for pat, pv in zip(pats, vecs, strict=True):
        hits = [i for i in pat["indicators"] if i.lower() in lower]
        score = 0.7 * _cos(qv, pv) + 0.3 * min(len(hits) / 4, 1.0)
        scored.append((score, pat, hits))
    scored.sort(key=lambda x: x[0], reverse=True)
    top = [
        {
            "id": p["id"],
            "category": p["category"],
            "score": round(s, 3),
            "indicator_hits": hits,
            "template": p["template"],
            "source_url": p["source_url"],
        }
        for s, p, hits in scored[:top_k]
    ]
    best = top[0] if top else None
    signals: list[Signal] = []
    if best and best["score"] >= 0.45:
        signals.append(
            Signal(
                id="strong_pattern_match",
                severity=Severity.RED,
                detail=f"Closely matches the known '{best['category']}' scam template "
                f"'{best['id']}' (score {best['score']}; indicators: {', '.join(best['indicator_hits'])}).",
            )
        )
    elif best and best["score"] >= 0.25:
        signals.append(
            Signal(
                id="partial_pattern_match",
                severity=Severity.AMBER,
                detail=f"Partially resembles the '{best['category']}' scam template '{best['id']}' "
                f"(score {best['score']}).",
            )
        )
    return ToolResult(
        tool="match_scam_pattern",
        status=Status.OK,
        summary=(
            f"Best match: {best['id']} ({best['category']}) score {best['score']}."
            if best and best["score"] >= 0.25
            else "No close match to the curated scam templates (dataset is small; absence is weak evidence)."
        ),
        signals=signals,
        evidence={"matches": top, "dataset_size": len(pats)},
        sources=sorted({m["source_url"] for m in top if m["score"] >= 0.25}),
    )
