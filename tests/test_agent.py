"""Agent loop tests with a scripted fake Claude client (no network, no API key)."""

from types import SimpleNamespace

from scamcheck.agent import ScamCheckAgent, apply_verdict_floor
from scamcheck.models import Severity, Signal, Status, ToolResult
from scamcheck.registry import anthropic_tools


def tool_use(id_, name, input_):
    return SimpleNamespace(type="tool_use", id=id_, name=name, input=input_)


def text(t):
    return SimpleNamespace(type="text", text=t)


def response(*blocks, stop="tool_use"):
    return SimpleNamespace(
        content=list(blocks),
        stop_reason=stop,
        usage=SimpleNamespace(input_tokens=10, output_tokens=5),
    )


class FakeClient:
    def __init__(self, script):
        self.script = list(script)
        self.calls = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append({**kwargs, "messages": [dict(m) for m in kwargs["messages"]]})
        return self.script.pop(0)


VERDICT = {
    "verdict": "likely_scam",
    "confidence": "high",
    "category": "bank_phishing",
    "headline": "Fake Maybank link.",
    "findings": [],
    "recommended_actions": ["Do not click."],
}
MSG = "MAYBANK: account suspended, verify at http://maybank2u-secure-verify.com/login"


def test_full_run_parallel_tools_then_verdict(settings, monkeypatch):
    monkeypatch.setattr(
        "scamcheck.registry.resolve_url_redirects",
        lambda url: ToolResult(
            tool="resolve_url_redirects", status=Status.UNVERIFIED, summary="offline"
        ),
    )
    client = FakeClient(
        [
            response(tool_use("t1", "extract_entities", {"message": MSG})),
            response(
                text("Checking the link and the claimed org."),
                tool_use("t2", "lookup_official_contact", {"org_name": "Maybank"}),
                tool_use("t3", "match_scam_pattern", {"message": MSG}),
                tool_use(
                    "t4",
                    "resolve_url_redirects",
                    {"url": "http://maybank2u-secure-verify.com/login"},
                ),
            ),
            response(tool_use("t5", "submit_verdict", VERDICT)),
        ]
    )
    agent = ScamCheckAgent(client=client, settings=settings)
    events = list(agent.check(MSG))
    kinds = [e["type"] for e in events]
    assert kinds.count("tool_call") == 4 and kinds.count("tool_result") == 4
    assert events[-2] == {"type": "verdict", "verdict": VERDICT}
    assert events[-1]["type"] == "done"
    # all three parallel results went back in ONE user message
    third_call_msgs = client.calls[2]["messages"]
    assert len([b for b in third_call_msgs[-1]["content"] if b["type"] == "tool_result"]) == 3
    # the pasted message is wrapped as untrusted data
    assert "<suspicious_message>" in client.calls[0]["messages"][0]["content"]


def test_nudges_once_when_model_skips_verdict(settings):
    client = FakeClient(
        [
            response(text("Looks fine to me."), stop="end_turn"),
            response(
                tool_use("v", "submit_verdict", {**VERDICT, "verdict": "insufficient_information"})
            ),
        ]
    )
    events = list(ScamCheckAgent(client=client, settings=settings).check("hello"))
    assert any(e["type"] == "verdict" for e in events)
    assert "submit_verdict" in client.calls[1]["messages"][-1]["content"][0]["text"]


def test_gives_fallback_verdict_if_model_never_submits(settings):
    client = FakeClient(
        [response(text("hmm"), stop="end_turn"), response(text("still"), stop="end_turn")]
    )
    events = list(ScamCheckAgent(client=client, settings=settings).check("hello"))
    v = next(e for e in events if e["type"] == "verdict")["verdict"]
    assert v["verdict"] == "insufficient_information"


def test_refusal_is_reported(settings):
    client = FakeClient([response(stop="refusal")])
    events = list(ScamCheckAgent(client=client, settings=settings).check("x"))
    assert events[-1]["type"] == "error"


def test_follow_up_question_merges_into_last_user_turn(settings):
    client = FakeClient(
        [
            response(tool_use("v", "submit_verdict", VERDICT)),
            response(text("Because the domain is not Maybank's."), stop="end_turn"),
        ]
    )
    agent = ScamCheckAgent(client=client, settings=settings)
    list(agent.check(MSG))
    events = list(agent.ask("why?"))
    roles = [m["role"] for m in client.calls[1]["messages"]]
    assert roles == ["user", "assistant", "user"]  # strict alternation preserved
    assert events[0] == {"type": "text", "text": "Because the domain is not Maybank's."}


def test_verdict_floor_overrides_legitimate_when_hard_red_flags():
    hard = ToolResult(
        tool="check_domain",
        status=Status.OK,
        summary="",
        signals=[
            Signal(id="brand_impersonation", severity=Severity.RED, detail="x", deterministic=True)
        ],
    )
    soft = ToolResult(
        tool="match_scam_pattern",
        status=Status.OK,
        summary="",
        signals=[Signal(id="strong_pattern_match", severity=Severity.RED, detail="y")],
    )
    v = apply_verdict_floor({**VERDICT, "verdict": "likely_legitimate"}, [hard, soft])
    assert v["verdict"] == "suspicious"
    assert v["floor_applied"]["reasons"] == ["brand_impersonation: x"]
    # heuristic-only red flags do not trigger the floor
    assert (
        apply_verdict_floor({**VERDICT, "verdict": "likely_legitimate"}, [soft])["verdict"]
        == "likely_legitimate"
    )


def test_tool_schemas_are_strict():
    for t in anthropic_tools():
        assert t["strict"] is True
        assert t["input_schema"]["additionalProperties"] is False
        assert set(t["input_schema"]["required"]) == set(t["input_schema"]["properties"])


def test_missing_credentials_is_a_clear_error(settings):
    class NoKeyClient(FakeClient):
        def _create(self, **kwargs):
            raise TypeError("Could not resolve authentication method. Expected one of api_key")

    events = list(ScamCheckAgent(client=NoKeyClient([]), settings=settings).check("x"))
    assert "ANTHROPIC_API_KEY" in events[0]["message"]
