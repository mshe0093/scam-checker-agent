from scamcheck import data
from scamcheck.tools.official_contact import lookup_official_contact
from scamcheck.tools.patterns import match_scam_pattern
from scamcheck.tools.phone import check_phone_number, normalise


def test_every_contact_and_policy_has_source_and_verification():
    for org in data.orgs():
        for item in org["contacts"] + org["policies"]:
            assert item["source_url"].startswith("https://"), org["id"]
            assert item["verification"] in {"official_page", "secondary_source", "unverified"}
    for p in data.patterns():
        assert p["source_url"].startswith("https://")


def test_lookup_by_alias_and_typo():
    assert lookup_official_contact("Lembaga Hasil").evidence["official_domains"] == [
        "hasil.gov.my"
    ]
    assert lookup_official_contact("maybnk").evidence["org"].startswith("Maybank")


def test_unknown_org_is_unverified_with_generic_channels():
    res = lookup_official_contact("Some Random Sdn Bhd")
    assert res.status == "unverified"
    assert any(g["value"] == "997" for g in res.evidence["generic_reporting"])


def test_pattern_match_parcel_and_bm():
    res = match_scam_pattern(
        "Your parcel is on hold due to incomplete address. Pay RM2 redelivery fee: bit.ly/x"
    )
    assert res.evidence["matches"][0]["category"] == "parcel_courier"
    assert res.signals and res.signals[0].id == "strong_pattern_match"
    bm = match_scam_pattern(
        "Tahniah! Pinjaman peribadi anda diluluskan tanpa dokumen, bayar yuran pemprosesan"
    )
    assert bm.evidence["matches"][0]["category"] == "loan_investment"


def test_pattern_no_match_for_benign_text():
    res = match_scam_pattern("Dinner at 8 at the usual mamak?")
    assert res.signals == []


def test_phone_normalise():
    assert normalise("012-345 6789") == "+60123456789"
    assert normalise("+60 3-5891 4744") == "+60358914744"
    assert normalise("1-300-88-5465") == "1300885465"


def test_phone_official_match_warns_about_spoofing():
    res = check_phone_number("03-5891 4744")
    assert res.signals[0].id == "matches_official_number"
    assert "spoofed" in res.signals[0].detail


def test_phone_mobile_is_amber_and_reputation_unverified():
    res = check_phone_number("011-2345 6789")
    assert res.status == "unverified"
    assert res.signals[0].id == "personal_mobile"
    assert "semakmule" in res.evidence["could_not_verify"][0]
