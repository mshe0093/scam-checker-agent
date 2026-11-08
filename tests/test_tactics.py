"""Scam-tactic detection (data/tactics.json) and how the rules engine explains its verdicts."""

import re

import pytest

from scamcheck import data
from scamcheck.models import Severity, Signal, Status, ToolResult
from scamcheck.registry import CATEGORIES
from scamcheck.rules_agent import decide
from scamcheck.tools import tactics
from scamcheck.tools.entities import extract_entities

# One message per tactic that must trigger it. Written for these tests, separate from the eval sets.
POSITIVE = {
    "apk_download": "Kad jemputan kahwin kami: hxxps://jemputan-digital[.]xyz/kad.apk",
    "remote_access_app": "Bank officer here. Please install AnyDesk so I can help secure your account.",
    "code_sharing_request": "Hi dear, I sent a code to your phone by mistake, please forward it to me.",
    "secret_credentials_request": "To unlock your account please reply with your username and password.",
    "bank_details_request": "Your refund is ready. Fill in your bank account number at the form.",
    "identity_document_request": "Sila hantar gambar IC dan selfie anda untuk pengesahan.",
    "safe_account_transfer": "Untuk keselamatan, pindahkan simpanan anda ke akaun selamat Bank Negara.",
    "police_case_transfer": "Your name appears in a money laundering investigation. Deposit RM20,000 to clear it.",
    "secrecy_demand": "Settle this today and please keep this confidential.",
    "gift_card_request": "Boss here. Buy 3 Razer Gold cards and send me the codes.",
    "account_rental": "Nak duit mudah? Sewa akaun bank anda RM800 sebulan.",
    "new_number_family": "Mak, ni nombor baru adik. Save ya.",
    "family_money_request": "Dad, my phone broke, this is my new number. Can you transfer RM600?",
    "off_platform_contact": "Interested? Add our admin on Telegram for details.",
    "job_task_offer": "Kerja sambilan online, pendapatan RM250 sehari, tiada pengalaman diperlukan.",
    "guaranteed_returns": "Invest RM1,000 today with guaranteed returns of 20% a month.",
    "crypto_pitch": "Join my USDT trading group, deposit as little as RM500.",
    "extortion": "We recorded your private video. Pay or we will send it to your contacts.",
    "advance_fee": "Your loan of RM20,000 is approved. Pay the processing fee first to release it.",
    "fake_payment_claim": "I already paid for your item. Claim the money here: carousel-pay.top/claim",
    "pay_before_delivery": "Barang ready stock, bayar deposit dulu baru saya pos.",
    "personal_account_payment": "Please bank in RM150 to Maybank account 5140 1234 5678.",
    "disconnection_threat": "Your water supply will be cut off tomorrow unless you settle the bill.",
    "aid_or_prize_claim": "Anda layak menerima bantuan RM300. Tuntut di bantuan-rakyat.site",
    "app_install_request": "Download our app here to get the promo: promo-rumah.xyz/get",
    "nsrc_impersonation": "Ini wakil NSRC. Akaun anda disyaki terlibat, sila hubungi kami segera.",
    "fund_recovery_offer": "Ditipu online? Kami pakar pemulihan dana, boleh dapatkan semula wang anda.",
    "endorsed_investment": "This platform is approved by Bank Negara. Invest RM250 and start earning today.",
    "qr_to_receive": "Imbas kod QR ini untuk terima bayaran balik anda.",
    "romance_money_request": "Honey, I'm stuck at the airport. Please send money for my ticket home.",
    "press_to_connect": "Your court summons is pending. Press 2 to speak to an officer.",
    "rental_deposit": "Rumah sewa masih ada. Saya outstation, bayar yuran tempahan dulu ya.",
}

# Genuine messages in the same style that must not trigger any tactic.
CLEAN = [
    "Your Grab verification code is 553201. Do not share this code with anyone.",
    "RM0 Maybank: Never share your TAC with anyone. Maybank will never ask for your password.",
    "Jangan kongsi kod TAC anda dengan sesiapa. Kod: 118822.",
    "Hi team, meeting moved to 3pm today. Please bring the report.",
    "Thanks for lunch! I've transferred RM20 to you just now.",
    "Shopee: Your order has been shipped. Track it in the Shopee app.",
    "Mak dah sampai rumah, nanti call nenek ya.",
    "Maybank: Enjoy 0% instalment for 12 months on selected purchases. T&C apply at maybank2u.com.my",
    "TNB: Your bill for October is RM88.10, due 25/11. Pay via the myTNB app.",
    "Download the MAE app from Google Play to manage your account.",
    # Genuine advisories mention the NSRC without claiming to be it.
    "If you have been scammed, call NSRC at 997 immediately to stop the transfer.",
    "Jika anda menjadi mangsa penipuan, hubungi NSRC 997 segera.",
    "Hi, is the room in Bangsar still available for rent? Can I view it this Saturday?",
    "Thanks for dining with us! You can pay at the counter with DuitNow QR or card.",
    "Securities Commission: check any investment offer on the SC Investment Checker first.",
]


def tactic_ids(message: str) -> set[str]:
    return {h["id"] for h in extract_entities(message).evidence["tactics"]}


@pytest.mark.parametrize("tactic_id", sorted(POSITIVE))
def test_each_tactic_fires_on_its_example(tactic_id):
    assert tactic_id in tactic_ids(POSITIVE[tactic_id])


def test_every_tactic_has_a_positive_example():
    assert {t.id for t in tactics.tactics()} == set(POSITIVE)


@pytest.mark.parametrize("message", CLEAN)
def test_genuine_messages_trigger_no_tactic(message):
    assert tactic_ids(message) == set()


def test_negation_only_applies_right_before_the_request():
    assert "code_sharing_request" not in tactic_ids("Never share your TAC with anyone.")
    # "not" earlier in the sentence doesn't cancel the request that follows.
    assert "code_sharing_request" in tactic_ids(
        "If this was not you, reply with the 6-digit TAC to cancel."
    )


def test_needs_url_tactics_need_a_link():
    assert "aid_or_prize_claim" not in tactic_ids(
        "Anda layak menerima bantuan RM300. Tuntut di kaunter."
    )


def test_tactic_signal_quotes_what_matched():
    sig = next(
        s
        for s in extract_entities(POSITIVE["safe_account_transfer"]).signals
        if s.id == "safe_account_transfer"
    )
    assert sig.deterministic and "'akaun selamat'" in sig.detail


# --- data integrity ---------------------------------------------------------------------------


def test_tactics_data_is_well_formed():
    for t in data.tactics():
        assert t["title"] and t["reason"] and t["detail"] and t["advice"]
        assert t["category"] in {*CATEGORIES, "other"}
        assert not (t.get("deterministic") and t["severity"] != "red"), t["id"]
        for group in t["all"]:
            for pattern in group:
                re.compile(pattern)


def test_brand_tokens_never_match_another_orgs_official_domain():
    orgs = data.orgs()
    for org in orgs:
        for token in org["brand_tokens"]:
            for other in orgs:
                if other["id"] == org["id"]:
                    continue
                for domain in other["official_domains"]:
                    assert token not in domain.replace(".", "").replace("-", ""), (token, domain)


def test_no_domain_is_official_for_two_orgs():
    owners: dict[str, str] = {}
    for org in data.orgs():
        for domain in org["official_domains"]:
            assert domain not in owners, (domain, owners.get(domain), org["id"])
            owners[domain] = org["id"]


def test_known_wrong_domains_are_not_official():
    official = {d for org in data.orgs() for d in org["official_domains"]}
    # mae.com.my is an English-learning site, not Maybank's MAE app; pbislamic.com.my is unregistered.
    assert "mae.com.my" not in official
    assert "pbislamic.com.my" not in official
    assert "affinalways.com" in official  # Affin's live site


def test_short_ids_do_not_match_inside_other_names():
    from scamcheck.tools.orgs import match_org

    # "sc" (Securities Commission) appears inside "nsrc"; it must not win.
    assert match_org("NSRC (National Scam Response Centre, 997)")["id"] == "nsrc"
    assert match_org("Securities Commission")["id"] == "sc"
    assert match_org("mayban")["id"] == "maybank"
    assert match_org("Unknown Trading Sdn Bhd") is None


def test_every_explanation_reason_is_a_known_signal_or_unused():
    reasons = data.explanations()["reasons"]
    assert all(isinstance(v, str) and v for v in reasons.values())


# --- rules engine decisions and explanations ----------------------------------------------------


def _ent(**over):
    base = {
        "urls": [],
        "phone_numbers": [],
        "claimed_orgs": [],
        "emails": [],
        "pressure_language": {},
        "strong_pressure": {},
    }
    return {**base, **over}


def _res(tool, *signals, evidence=None):
    return ToolResult(
        tool=tool, status=Status.OK, summary="", signals=list(signals), evidence=evidence or {}
    )


def _entities_result(message):
    res = extract_entities(message)
    return res.evidence, res


def test_naming_an_org_is_not_evidence_of_legitimacy():
    ent = _ent(
        claimed_orgs=[{"id": "bnm", "name": "Bank Negara Malaysia (BNM)", "matched": "bnm"}]
    )
    v = decide(ent, [_res("extract_entities")])
    assert v["verdict"] == "insufficient_information"
    assert "Bank Negara Malaysia" in v["headline"]


def test_macau_scam_without_links_is_a_likely_scam():
    ent, res = _entities_result(
        "Ini pegawai Bank Negara. Akaun anda terlibat dalam kes pengubahan wang haram. "
        "Pindahkan semua wang ke akaun selamat. Jangan beritahu sesiapa."
    )
    v = decide(ent, [res])
    assert v["verdict"] == "likely_scam" and v["confidence"] == "high"
    assert v["category"] == "government_impersonation"
    assert "safe account" in v["headline"]


def test_one_weak_hint_is_not_a_warning():
    weak = Signal(id="partial_pattern_match", severity=Severity.AMBER, detail="")
    v = decide(_ent(), [_res("match_scam_pattern", weak)])
    assert v["verdict"] == "insufficient_information"


def test_red_tactic_with_strong_pressure_is_likely_scam():
    ent, res = _entities_result(
        "Pelaburan emas, pulangan 15% sebulan dijamin. Daftar sekarang, slot terhad!"
    )
    v = decide(ent, [res])
    assert v["verdict"] == "likely_scam"
    assert v["category"] == "loan_investment"


def test_partner_asking_for_grocery_money_is_not_warned_about():
    # The romance tactic is a weak hint (weight 1): on its own it must not trigger a warning.
    ent, res = _entities_result("Darling, can you transfer RM50 for groceries? Love you!")
    assert "romance_money_request" in {h["id"] for h in ent["tactics"]}
    assert decide(ent, [res])["verdict"] == "insufficient_information"


def test_fake_nsrc_officer_gets_nsrc_advice_not_another_orgs():
    from scamcheck.tools.official_contact import lookup_official_contact

    msg = "This is an officer from the NSRC. Your line will be disconnected. Press 1 now."
    ent, res = _entities_result(msg)
    contact = lookup_official_contact(ent["claimed_orgs"][0]["name"])
    v = decide(ent, [res, contact])
    assert v["verdict"] == "likely_scam"
    assert "NSRC" in v["headline"]
    assert not any("Securities Commission" in a for a in v["recommended_actions"])


def test_everyday_words_are_not_pressure():
    ent, res = _entities_result("See you today, I'll pay you back now.")
    assert ent["strong_pressure"] == {}
    assert decide(ent, [res])["verdict"] == "insufficient_information"


def test_advice_is_tailored_and_not_repeated():
    ent, res = _entities_result(POSITIVE["apk_download"] + " Download the app now.")
    actions = decide(ent, [res])["recommended_actions"]
    assert any(".apk" in a for a in actions)
    assert len(actions) == len(set(actions))
    # The .apk advice and the generic "install an app" advice are the same kind; only one is shown.
    assert sum("Google Play" in a for a in actions) == 1


def test_official_contact_comes_from_the_dataset():
    contact = _res(
        "lookup_official_contact",
        evidence={
            "org": "TNB (Tenaga Nasional Berhad)",
            "type": "utility",
            "official_domains": ["tnb.com.my"],
            "contacts": [
                {
                    "label": "TNB CareLine",
                    "value": "1300-88-5454",
                    "verification": "official_page",
                    "source_url": "https://www.tnb.com.my/scam-alert/impersonation-scam/",
                }
            ],
        },
    )
    ent, res = _entities_result("TNB: bekalan elektrik anda akan dipotong. Bayar segera.")
    v = decide(ent, [res, contact])
    assert any("1300-88-5454" in a for a in v["recommended_actions"])


def test_headline_names_the_organisation_for_domain_signals():
    mismatch = Signal(
        id="claimed_org_domain_mismatch", severity=Severity.RED, detail="", deterministic=True
    )
    ent = _ent(
        urls=["https://maybank-help.top"],
        claimed_orgs=[
            {"id": "maybank", "name": "Maybank (Malayan Banking Berhad)", "matched": "maybank"}
        ],
    )
    v = decide(ent, [_res("check_domain", mismatch)])
    assert "not Maybank's real website" in v["headline"]
