"""API tests with a fake agent: SSE framing, sessions, limits. No network, no API key."""

import json

import pytest
from fastapi.testclient import TestClient

from scamcheck.api import SessionStore, create_app


class FakeAgent:
    def __init__(self):
        self.asked = []

    def check(self, message):
        yield {
            "type": "tool_call",
            "id": "t1",
            "name": "extract_entities",
            "input": {"message": message},
        }
        yield {"type": "verdict", "verdict": {"verdict": "likely_scam"}}
        yield {"type": "done", "usage": {}}

    def ask(self, question):
        self.asked.append(question)
        yield {"type": "text", "text": f"answer to {question}"}
        yield {"type": "done", "usage": {}}


class BrokenAgent(FakeAgent):
    def check(self, message):
        yield {"type": "tool_call", "id": "t1", "name": "x", "input": {}}
        raise RuntimeError("secret internals")


def parse_sse(text):
    events = []
    for block in text.strip().split("\n\n"):
        lines = dict(line.split(": ", 1) for line in block.splitlines())
        data = json.loads(lines["data"])
        assert lines["event"] == data["type"]
        events.append(data)
    return events


@pytest.fixture
def client():
    return TestClient(create_app(agent_factory=FakeAgent, rate_limit=(100, 60)))


def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_check_streams_session_then_trace(client):
    r = client.post("/api/check", json={"message": "MAYBANK: verify now"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    events = parse_sse(r.text)
    assert [e["type"] for e in events] == ["session", "tool_call", "verdict", "done"]
    assert len(events[0]["session_id"]) >= 16


def test_follow_up_uses_same_session(client):
    sid = parse_sse(client.post("/api/check", json={"message": "x"}).text)[0]["session_id"]
    events = parse_sse(client.post("/api/ask", json={"session_id": sid, "question": "why?"}).text)
    assert events[0] == {"type": "text", "text": "answer to why?"}


def test_unknown_session_is_404(client):
    r = client.post("/api/ask", json={"session_id": "doesnotexist", "question": "why?"})
    assert r.status_code == 404


@pytest.mark.parametrize("body", [{"message": ""}, {"message": "x" * 4001}, {}])
def test_message_validation(client, body):
    assert client.post("/api/check", json=body).status_code == 422


def test_rate_limit():
    c = TestClient(create_app(agent_factory=FakeAgent, rate_limit=(2, 60)))
    codes = [c.post("/api/check", json={"message": "x"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_agent_crash_becomes_error_event_without_details():
    c = TestClient(create_app(agent_factory=BrokenAgent, rate_limit=(100, 60)))
    events = parse_sse(c.post("/api/check", json={"message": "x"}).text)
    assert events[-1]["type"] == "error"
    assert "secret" not in events[-1]["message"]


def test_session_store_expires_and_caps():
    store = SessionStore(ttl=-1)  # everything is immediately stale
    sid, _ = store.create(FakeAgent())
    assert store.get(sid) is None
    capped = SessionStore(max_sessions=2)
    ids = [capped.create(FakeAgent())[0] for _ in range(3)]
    assert len(capped) == 2 and capped.get(ids[0]) is None
