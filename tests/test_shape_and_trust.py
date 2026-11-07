"""Lookalike fuzzing, IDN folding, URL-shape signals, trust signals and the rules-engine weights."""

from datetime import UTC, datetime

from conftest import rdap_client

from scamcheck.agent import apply_verdict_floor
from scamcheck.models import Severity, Signal, Status, ToolResult
from scamcheck.rules_agent import decide, never_legitimate
from scamcheck.tools.domain import check_domain, decode_host, random_looking, skeleton
from scamcheck.tools.entities import extract_entities

NOW = datetime(2026, 11, 7, tzinfo=UTC)
OLD = "2015-01-01T00:00:00Z"
# "maybank2u" spelled with Cyrillic em and a, built from code points so the test source stays ASCII.
CYRILLIC_MAYBANK = "\u043c\u0430ybank2u"


def ids(res):
    return {s.id for s in res.signals}


def check(url, created=OLD, claimed=None, settings=None):
    return check_domain(url, claimed, client=rdap_client(created), settings=settings, now=NOW)


# --- IDN / punycode -------------------------------------------------------------------------


def test_skeleton_folds_other_alphabets_and_accents():
    assert skeleton(CYRILLIC_MAYBANK) == "maybank2u"
    assert skeleton("p\u00fablicbank") == "publicbank"  # u with acute accent


def test_punycode_host_is_decoded():
    puny = (CYRILLIC_MAYBANK + ".com").encode("idna").decode()
    assert puny.startswith("xn--")
    assert decode_host(puny) == CYRILLIC_MAYBANK + ".com"


def test_punycode_lookalike_is_caught_without_a_claimed_org(settings):
    puny = (CYRILLIC_MAYBANK + ".com").encode("idna").decode()
    res = check(f"https://{puny}/", settings=settings)
    sig = next(s for s in res.signals if s.id in {"brand_impersonation", "lookalike_domain"})
    assert sig.deterministic and "another alphabet" in sig.detail
    assert res.evidence["unicode_host"] == CYRILLIC_MAYBANK + ".com"


def test_unrelated_idn_host_is_only_amber(settings):
    res = check("https://xn--caf-dma.com/", settings=settings)  # café.com
    assert "idn_host" in ids(res)
    assert res.hard_red_flags == []


# --- dnstwist permutations and tighter Levenshtein -------------------------------------------


def test_dnstwist_permutation_names_the_technique(settings):
    res = check("https://maybamk2u.com.my/", settings=settings)
    sig = next(s for s in res.signals if s.id == "lookalike_domain")
    assert "maybank2u.com.my" in sig.detail and "permutation" in sig.detail


def test_short_names_need_a_closer_match(settings):
    # "hlb", "bnm", "pos" are too short to fuzz; one edit away from them is not flagged.
    assert check("https://hlc.com/", settings=settings).hard_red_flags == []


def test_embedded_official_domain(settings):
    res = check("https://maybank2u.com.my.secure-login.top/", settings=settings)
    assert "embedded_official_domain" in ids(res)


# --- URL shape ------------------------------------------------------------------------------


def test_login_path_on_unofficial_domain(settings):
    res = check("https://example-shop.com/akaun/sahkan?x=1", settings=settings)
    sig = next(s for s in res.signals if s.id == "phishing_path_keywords")
    assert "akaun" in sig.detail and "sahkan" in sig.detail


def test_login_path_on_official_domain_is_fine(settings):
    res = check_domain("https://www.maybank2u.com.my/login", settings=settings, now=NOW)
    assert "phishing_path_keywords" not in ids(res)


def test_stacked_subdomains(settings):
    res = check("https://a.b.c.example.com/", settings=settings)
    assert "excessive_subdomains" in ids(res)


def test_random_looking_names():
    assert random_looking("xk7q9zt2wpl")
    assert not random_looking("touchngo")
    assert not random_looking("publicbank")


# --- trust signals --------------------------------------------------------------------------


def test_old_domain_earns_trust(settings):
    res = check("https://example-clinic.com.my/", settings=settings)
    assert "established_domain" in ids(res)


def test_old_domain_with_login_path_earns_no_trust(settings):
    # Hacked old sites keep their age; a login-looking path on them is not vouched for.
    res = check("https://example-clinic.com.my/wp-content/secure/login", settings=settings)
    assert "established_domain" not in ids(res)
    assert "not counted as trust" in next(s for s in res.signals if s.id == "domain_age").detail


def test_old_lookalike_earns_no_trust(settings):
    res = check("https://maybamk2u.com.my/", settings=settings)
    assert "established_domain" not in ids(res)


def test_protective_tac_wording_is_not_a_credential_request():
    ent = extract_entities(
        "RM0 MAYBANK: Your TAC is 482913. NEVER share your TAC with anyone."
    ).evidence
    assert "credential_request" not in ent["pressure_language"]
    assert ent["security_advice"] == ["never share"]


def test_protective_wording_with_a_link_gets_no_green():
    res = extract_entities("Never share your TAC. Verify at http://mbb-verify.top/login")
    assert "security_advice" not in ids(res)
    assert "credential_request" in res.evidence["pressure_language"]  # "verify" still counts


# --- rules engine weights and caps ----------------------------------------------------------


def _ent(**over):
    base = {
        "urls": [],
        "phone_numbers": [],
        "claimed_orgs": [],
        "emails": [],
        "pressure_language": {},
    }
    return {**base, **over}


def _res(tool, *signals, status=Status.OK):
    return ToolResult(tool=tool, status=status, summary="", signals=list(signals))


def test_green_official_number_outweighs_scary_wording():
    results = [
        _res(
            "extract_entities", Signal(id="pressure_tactics", severity=Severity.AMBER, detail="")
        ),
        _res(
            "check_phone_number",
            Signal(id="matches_official_number", severity=Severity.GREEN, detail=""),
        ),
        _res(
            "match_scam_pattern",
            Signal(id="partial_pattern_match", severity=Severity.AMBER, detail=""),
        ),
    ]
    v = decide(
        _ent(phone_numbers=["03-5891 4744"], pressure_language={"threat": ["blocked"]}), results
    )
    assert v["verdict"] == "likely_legitimate"


def test_unresolved_short_link_can_never_be_cleared():
    short = Signal(id="url_shortener", severity=Severity.AMBER, detail="")
    green = Signal(id="established_domain", severity=Severity.GREEN, detail="")
    results = [
        _res("resolve_url_redirects", status=Status.UNVERIFIED),
        _res("check_domain", short, green, Signal(id="x", severity=Severity.GREEN, detail="")),
    ]
    assert never_legitimate(results)
    v = decide(_ent(urls=["https://bit.ly/abc"]), results)
    assert v["verdict"] == "suspicious"
    assert any(f["check"] == "Cannot clear" for f in v["findings"])


def test_resolved_short_link_is_not_capped():
    results = [
        _res(
            "resolve_url_redirects",
            Signal(id="shortener_resolved", severity=Severity.INFO, detail=""),
        ),
        _res("check_domain", Signal(id="url_shortener", severity=Severity.AMBER, detail="")),
    ]
    assert never_legitimate(results) == []


def test_agent_floor_applies_short_link_cap():
    results = [
        _res("check_domain", Signal(id="url_shortener", severity=Severity.AMBER, detail=""))
    ]
    out = apply_verdict_floor({"verdict": "likely_legitimate", "confidence": "low"}, results)
    assert out["verdict"] == "suspicious" and out["floor_applied"]["reasons"]
