"""A short warning people can forward to family on WhatsApp, in English and Bahasa Malaysia.

Built from the verdict and the curated dataset only. It deliberately never repeats the message's
links or phone numbers, so forwarding a warning can't spread the scam.
"""

from __future__ import annotations

import os
from typing import Any

from scamcheck.models import ToolResult

_LABEL = {
    "en": {
        "likely_scam": "⚠️ LIKELY SCAM",
        "suspicious": "⚠️ SUSPICIOUS",
        "likely_legitimate": "✅ Probably genuine",
        "insufficient_information": "❔ Can't tell",
    },
    "ms": {
        "likely_scam": "⚠️ KEMUNGKINAN BESAR SCAM",
        "suspicious": "⚠️ MENCURIGAKAN",
        "likely_legitimate": "✅ Mungkin tulen",
        "insufficient_information": "❔ Tidak dapat dipastikan",
    },
}
_CATEGORY = {
    "en": {
        "bank_phishing": "Fake bank / e-wallet message",
        "parcel_courier": "Fake parcel / courier message",
        "government_impersonation": "Fake government or police message",
        "loan_investment": "Loan or investment scam",
        "job_task": "Fake job / task scam",
        "prize": "Fake prize or aid",
        "impersonation": "Someone pretending to be family, a boss or a partner",
        "malware_apk": "Malicious app (.apk)",
        "account_takeover": "Account takeover (code theft)",
        "money_mule": "Money-mule recruitment",
        "online_shopping": "Online shopping or rental scam",
        "extortion": "Extortion",
        "utility_telco": "Fake utility or telco message",
    },
    "ms": {
        "bank_phishing": "Mesej bank / e-dompet palsu",
        "parcel_courier": "Mesej bungkusan / kurier palsu",
        "government_impersonation": "Mesej kerajaan atau polis palsu",
        "loan_investment": "Scam pinjaman atau pelaburan",
        "job_task": "Scam kerja / tugasan palsu",
        "prize": "Hadiah atau bantuan palsu",
        "impersonation": "Menyamar sebagai keluarga, majikan atau pasangan",
        "malware_apk": "Aplikasi berbahaya (.apk)",
        "account_takeover": "Curi akaun (kod pengesahan)",
        "money_mule": "Rekrut akaun keldai",
        "online_shopping": "Scam beli-belah atau sewa dalam talian",
        "extortion": "Peras ugut",
        "utility_telco": "Mesej utiliti atau telco palsu",
    },
}
_ADVICE = {
    "en": {
        "likely_scam": [
            "Don't click any link, reply, or call numbers in the message.",
            "Never share your TAC, OTP, PIN or passwords.",
            "Lost money? Call your bank and NSRC 997 immediately.",
        ],
        "suspicious": [
            "Don't use the links or numbers in the message.",
            "Check through the official app, or a number you look up yourself.",
        ],
        "likely_legitimate": ["If in doubt, still use the official app or hotline."],
        "insufficient_information": [
            "If they ask for money or codes, confirm who they are another way first.",
        ],
    },
    "ms": {
        "likely_scam": [
            "Jangan klik pautan, balas, atau hubungi nombor dalam mesej itu.",
            "Jangan sesekali kongsi TAC, OTP, PIN atau kata laluan.",
            "Sudah hilang wang? Hubungi bank anda dan NSRC 997 segera.",
        ],
        "suspicious": [
            "Jangan guna pautan atau nombor dalam mesej itu.",
            "Semak melalui aplikasi rasmi, atau nombor yang anda cari sendiri.",
        ],
        "likely_legitimate": ["Jika ragu-ragu, gunakan aplikasi atau talian rasmi."],
        "insufficient_information": [
            "Jika mereka minta wang atau kod, sahkan identiti mereka dengan cara lain dahulu.",
        ],
    },
}
_TEXT = {
    "en": {
        "type": "Type",
        "why": "Why",
        "todo": "What to do",
        "official": "Official line",
        "footer": "Checked with Scam Checker",
    },
    "ms": {
        "type": "Jenis",
        "why": "Sebab",
        "todo": "Apa perlu dibuat",
        "official": "Talian rasmi",
        "footer": "Disemak dengan Scam Checker",
    },
}
_ENGINE_SUFFIX = " (rules engine, no AI)"


def _official(results: list[ToolResult]) -> str | None:
    contact = next((r for r in results if r.tool == "lookup_official_contact"), None)
    if not contact or not contact.evidence.get("org"):
        return None
    for c in contact.evidence.get("contacts", []):
        if c["verification"] in {"official_page", "secondary_source"} and not c[
            "value"
        ].startswith("https://"):
            return f"{contact.evidence['org']}: {c['value']} ({c['label']})"
    return None


def share_text(verdict: dict[str, Any], results: list[ToolResult], lang: str) -> str:
    kind = verdict.get("verdict", "insufficient_information")
    t = _TEXT[lang]
    lines = [f"{_LABEL[lang].get(kind, kind)}"]
    category = _CATEGORY[lang].get(verdict.get("category", ""))
    if category and kind in {"likely_scam", "suspicious"}:
        lines.append(f"{t['type']}: {category}")
    if lang == "en" and verdict.get("headline"):
        why = verdict["headline"].removesuffix(_ENGINE_SUFFIX)
        for lead in ("Likely scam: ", "Warning signs: ", "Nothing suspicious found: "):
            why = why.removeprefix(lead)
        lines.append(f"{t['why']}: {why[0].upper()}{why[1:]}")
    lines.append("")
    lines.append(f"{t['todo']}:")
    lines += [f"• {a}" for a in _ADVICE[lang][kind]]
    official = _official(results)
    if official and kind in {"likely_scam", "suspicious"}:
        lines.append(f"• {t['official']}: {official}")
    url = os.getenv("SCAMCHECK_PUBLIC_URL", "").strip()
    lines.append("")
    lines.append(f"{t['footer']}" + (f": {url}" if url else ""))
    return "\n".join(lines)


def with_share(verdict: dict[str, Any], results: list[ToolResult]) -> dict[str, Any]:
    """Return the verdict with a `share` field: {"en": ..., "ms": ...}."""
    return {
        **verdict,
        "share": {lang: share_text(verdict, results, lang) for lang in ("en", "ms")},
    }
