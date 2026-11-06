from datetime import UTC, datetime

from conftest import fake_whois, rdap_404_client, rdap_client

from scamcheck.tools.domain import check_domain, levenshtein, registrable
from scamcheck.tools.registration import from_whois

NOW = datetime(2026, 11, 6, tzinfo=UTC)


def ids(res):
    return {s.id for s in res.signals}


def test_registrable_domain_uses_public_suffix():
    assert registrable("login.maybank2u.com.my") == "maybank2u.com.my"
    assert registrable("a.b.example.co.uk") == "example.co.uk"


def test_official_domain_is_green_and_skips_network(settings):
    res = check_domain("https://www.maybank2u.com.my/home", settings=settings, now=NOW)
    assert "official_domain" in ids(res)
    assert res.hard_red_flags == []


def test_spec_example_brand_impersonation_and_new_domain(settings):
    res = check_domain(
        "http://maybank2u-secure-verify.com/login",
        "Maybank",
        client=rdap_client("2026-10-25T00:00:00Z"),
        settings=settings,
        now=NOW,
    )
    assert {"brand_impersonation", "claimed_org_domain_mismatch", "very_new_domain"} <= ids(res)
    assert res.evidence["age_days"] == 12


def test_homoglyph_lookalike_is_caught(settings):
    res = check_domain(
        "rnaybank2u.com", client=rdap_client("2020-01-01T00:00:00Z"), settings=settings, now=NOW
    )
    assert ids(res) & {"brand_impersonation", "lookalike_domain"}


def test_government_claim_on_non_gov_my_domain(settings):
    res = check_domain(
        "lhdn-refund.online",
        "LHDN",
        client=rdap_client("2026-11-01T00:00:00Z"),
        settings=settings,
        now=NOW,
    )
    sig = next(s for s in res.signals if s.id == "claimed_org_domain_mismatch")
    assert ".gov.my" in sig.detail
    assert "high_abuse_tld" in ids(res)


def test_ip_literal(settings):
    res = check_domain("http://203.0.113.9/login", settings=settings)
    assert ids(res) == {"ip_literal_host"}


def test_my_domain_falls_back_to_whois(settings):
    whois = fake_whois(
        "Domain Name: pos-laju-my.com.my\nCreation Date: 2026-11-01T02:00:00.000Z\n"
    )
    res = check_domain(
        "pos-laju-my.com.my", client=rdap_404_client(), whois=whois, settings=settings, now=NOW
    )
    assert res.evidence["registration_source"] == "whois:whois.mynic.my"
    assert "very_new_domain" in ids(res)


def test_unregistered_domain_reported_not_guessed(settings):
    whois = fake_whois('No match for "GONE-PHISH.COM".\n>>> Last update <<<')
    res = check_domain(
        "gone-phish.com", client=rdap_404_client(), whois=whois, settings=settings, now=NOW
    )
    assert "unregistered_domain" in ids(res)


def test_no_registration_data_is_unverified_not_invented(settings):
    res = check_domain(
        "example-unknown.com",
        client=rdap_404_client(),
        whois=fake_whois("???"),
        settings=settings,
        now=NOW,
    )
    assert "created" not in res.evidence
    assert any("registration date" in u for u in res.evidence["could_not_verify"])
    assert any("Safe Browsing" in u for u in res.evidence["could_not_verify"])


def test_whois_footer_not_found_text_does_not_mark_unregistered():
    text = (
        "Domain Name: X.COM\nCreation Date: 2001-01-01T00:00:00Z\n"
        + "\n" * 10
        + "records not found ..."
    )
    reg = from_whois("x.com", fake_whois(text))
    assert reg.created is not None and reg.registered is None


def test_levenshtein():
    assert levenshtein("maybank", "maybamk") == 1
    assert levenshtein("cimb", "cimb") == 0
