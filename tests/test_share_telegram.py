"""Shareable EN/BM summaries and the optional Telegram webhook."""

from fastapi.testclient import TestClient

from scamcheck.api import create_app
from scamcheck.models import Status, ToolResult
from scamcheck.share import share_text, with_share

SCAM = {
    "verdict": "likely_scam",
    "category": "bank_phishing",
    "headline": "Likely scam: the link is not Maybank's real website. (rules engine, no AI)",
}
CONTACT = ToolResult(
    tool="lookup_official_contact",
    status=Status.OK,
    summary="",
    evidence={
        "org": "Maybank",
        "contacts": [
            {
                "label": "24h Fraud Hotline",
                "value": "03-5891 4744",
                "verification": "official_page",
                "source_url": "https://example.invalid",
            }
        ],
    },
)


def test_share_has_both_languages_and_the_official_line():
    v = with_share(SCAM, [CONTACT])
    assert "LIKELY SCAM" in v["share"]["en"]
    assert "KEMUNGKINAN BESAR SCAM" in v["share"]["ms"]
    assert "03-5891 4744" in v["share"]["en"] and "03-5891 4744" in v["share"]["ms"]
    assert "NSRC 997" in v["share"]["ms"]
    # The "Why" line drops the verdict prefix and the engine label.
    assert "Why: The link is not Maybank's real website." in v["share"]["en"]
    assert "rules engine" not in v["share"]["en"]


def test_share_never_repeats_the_scam_link():
    verdict = {**SCAM, "findings": [{"detail": "maybank2u-verify.top"}]}
    text = share_text(verdict, [], "en") + share_text(verdict, [], "ms")
    assert "maybank2u-verify.top" not in text


def test_share_footer_uses_public_url(monkeypatch):
    monkeypatch.setenv("SCAMCHECK_PUBLIC_URL", "https://scamcheck.example")
    assert share_text(SCAM, [], "en").endswith("https://scamcheck.example")


def test_rules_engine_verdict_carries_share():
    from scamcheck.rules_agent import RulesAgent

    a = RulesAgent()
    list(a.check("Hi, are we still on for lunch?"))
    assert set(a.verdict["share"]) == {"en", "ms"}


# --- Telegram -----------------------------------------------------------------------------------


class FakeAgent:
    engine = "fake"

    def check(self, message):
        yield {"type": "verdict", "verdict": with_share(SCAM, [CONTACT])}


def _bot(monkeypatch, rate=(100, 60)):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123:abc")
    monkeypatch.setenv("TELEGRAM_WEBHOOK_SECRET", "s3cret")
    app = create_app(agent_factory=FakeAgent, rate_limit=rate)
    sent: list[tuple[int, str]] = []
    app.state.telegram_set_sender(lambda chat, text: sent.append((chat, text)))
    return TestClient(app), sent


def _update(text, lang="en", chat=42):
    return {"message": {"chat": {"id": chat}, "from": {"language_code": lang}, "text": text}}


HDR = {"x-telegram-bot-api-secret-token": "s3cret"}


def test_webhook_rejects_wrong_secret(monkeypatch):
    c, sent = _bot(monkeypatch)
    r = c.post(
        "/api/telegram/webhook",
        json=_update("hi"),
        headers={"x-telegram-bot-api-secret-token": "nope"},
    )
    assert r.status_code == 403 and sent == []


def test_webhook_replies_with_the_share_text(monkeypatch):
    c, sent = _bot(monkeypatch)
    assert (
        c.post(
            "/api/telegram/webhook", json=_update("MAYBANK: verify now"), headers=HDR
        ).status_code
        == 200
    )
    assert sent[0][0] == 42
    assert "LIKELY SCAM" in sent[-1][1]


def test_webhook_uses_bm_for_malay_users_and_commands(monkeypatch):
    c, sent = _bot(monkeypatch)
    c.post("/api/telegram/webhook", json=_update("mesej", lang="ms", chat=7), headers=HDR)
    assert "KEMUNGKINAN BESAR SCAM" in sent[-1][1]
    c.post("/api/telegram/webhook", json=_update("/en", chat=7), headers=HDR)
    c.post("/api/telegram/webhook", json=_update("mesej", chat=7), headers=HDR)
    assert "LIKELY SCAM" in sent[-1][1]


def test_webhook_rate_limits_per_chat(monkeypatch):
    c, sent = _bot(monkeypatch, rate=(1, 60))
    c.post("/api/telegram/webhook", json=_update("one"), headers=HDR)
    c.post("/api/telegram/webhook", json=_update("two"), headers=HDR)
    assert "Too many checks" in sent[-1][1]


def test_webhook_absent_when_not_configured(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    c = TestClient(create_app(agent_factory=FakeAgent, rate_limit=(100, 60)))
    assert c.post("/api/telegram/webhook", json=_update("hi"), headers=HDR).status_code in {
        404,
        405,
    }
