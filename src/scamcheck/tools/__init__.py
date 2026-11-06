"""Verification tools. Plain Python, no LLM inside; each returns a ToolResult."""

from scamcheck.tools.domain import check_domain
from scamcheck.tools.entities import extract_entities
from scamcheck.tools.official_contact import lookup_official_contact
from scamcheck.tools.patterns import match_scam_pattern
from scamcheck.tools.phone import check_phone_number
from scamcheck.tools.redirects import resolve_url_redirects

__all__ = [
    "check_domain",
    "check_phone_number",
    "extract_entities",
    "lookup_official_contact",
    "match_scam_pattern",
    "resolve_url_redirects",
]
