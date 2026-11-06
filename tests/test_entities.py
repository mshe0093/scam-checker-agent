from scamcheck.tools.entities import extract_entities

SPEC_EXAMPLE = (
    "MAYBANK: Your acc has been suspended due to suspicious activity. Verify now to avoid "
    "permanent lock: http://maybank2u-secure-verify.com/login"
)


def test_spec_example_extracts_url_org_and_pressure():
    ev = extract_entities(SPEC_EXAMPLE).evidence
    assert ev["urls"] == ["http://maybank2u-secure-verify.com/login"]
    assert ev["claimed_orgs"][0]["id"] == "maybank"
    assert {"threat", "credential_request"} <= set(ev["pressure_language"])


def test_schemeless_and_defanged_urls():
    ev = extract_entities("Track at poslaju-track[.]xyz/abc or hxxps://bit.ly/3xYz now").evidence
    assert "poslaju-track.xyz/abc" in ev["urls"]
    assert "https://bit.ly/3xYz" in ev["urls"]


def test_email_domain_not_reported_as_url():
    ev = extract_entities("Reply to support@hasil-refund.com for your refund").evidence
    assert ev["emails"] == ["support@hasil-refund.com"]
    assert ev["urls"] == []


def test_malaysian_phone_formats_and_amounts():
    ev = extract_entities(
        "Call 012-345 6789 or +60 3-5891 4744 or 1-300-88-6688. Fee RM 1,250.50"
    ).evidence
    assert len(ev["phone_numbers"]) == 3
    assert ev["amounts"] == ["RM 1,250.50"]


def test_bahasa_malaysia_pressure_terms():
    res = extract_entities("Akaun anda telah disekat. Sila sahkan segera di pautan.")
    assert "threat" in res.evidence["pressure_language"]
    assert any(s.id == "pressure_tactics" for s in res.signals)


def test_benign_message_has_no_signals():
    res = extract_entities("See you at lunch tomorrow?")
    assert res.signals == []
    assert res.evidence["urls"] == []
