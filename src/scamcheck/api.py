"""HTTP API: Server-Sent Events streams of the agent's trace, plus follow-up Q&A sessions.

POST /api/check  {"message": "..."}                    -> SSE: session, tool_call, tool_result, text, verdict, done
POST /api/ask    {"session_id": "...", "question": "..."} -> SSE: text, tool_call, tool_result, done
GET  /api/health

Privacy: message text is never logged or persisted. Sessions live in memory and expire after
SESSION_TTL seconds.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from scamcheck import __version__
from scamcheck.agent import ScamCheckAgent
from scamcheck.rules_agent import RulesAgent

MAX_MESSAGE_CHARS = 4000
MAX_QUESTION_CHARS = 1000
SESSION_TTL = 30 * 60
MAX_SESSIONS = 500
MAX_FOLLOW_UPS = 10
RATE_LIMIT = (10, 10 * 60)  # 10 requests per 10 minutes per client IP


class CheckRequest(BaseModel):
    message: str = Field(min_length=1, max_length=MAX_MESSAGE_CHARS)


class AskRequest(BaseModel):
    session_id: str = Field(min_length=8, max_length=64)
    question: str = Field(min_length=1, max_length=MAX_QUESTION_CHARS)


@dataclass
class Session:
    agent: Any
    last_used: float = field(default_factory=time.monotonic)
    follow_ups: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)


class SessionStore:
    def __init__(self, ttl: float = SESSION_TTL, max_sessions: int = MAX_SESSIONS) -> None:
        self.ttl, self.max_sessions = ttl, max_sessions
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def _evict(self, now: float) -> None:
        for sid in [s for s, v in self._sessions.items() if now - v.last_used > self.ttl]:
            del self._sessions[sid]
        while len(self._sessions) >= self.max_sessions:  # drop the least recently used
            oldest = min(self._sessions, key=lambda s: self._sessions[s].last_used)
            del self._sessions[oldest]

    def create(self, agent: Any) -> tuple[str, Session]:
        with self._lock:
            self._evict(time.monotonic())
            sid = secrets.token_urlsafe(16)
            session = Session(agent=agent)
            self._sessions[sid] = session
            return sid, session

    def get(self, sid: str) -> Session | None:
        with self._lock:
            now = time.monotonic()
            self._evict(now)
            session = self._sessions.get(sid)
            if session:
                session.last_used = now
            return session

    def __len__(self) -> int:
        return len(self._sessions)


class RateLimiter:
    def __init__(self, limit: int, window: float) -> None:
        self.limit, self.window = limit, window
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True


def sse(event: dict[str, Any]) -> str:
    return f"event: {event['type']}\ndata: {json.dumps(event, default=str)}\n\n"


def _stream(
    events: Iterator[dict[str, Any]], session: Session, first: dict | None
) -> Iterator[str]:
    # One request at a time per session: the agent's message history is not thread-safe.
    if not session.lock.acquire(blocking=False):
        yield sse({"type": "error", "message": "This session is busy with another request."})
        return
    try:
        if first:
            yield sse(first)
        for ev in events:
            yield sse(ev)
    except Exception as exc:  # never leak a stack trace into the stream
        yield sse({"type": "error", "message": f"Internal error ({type(exc).__name__})."})
    finally:
        session.last_used = time.monotonic()
        session.lock.release()


def default_engine() -> tuple[str, Callable[[], Any]]:
    """SCAMCHECK_ENGINE=claude|rules|auto (default auto: Claude when credentials are set)."""
    choice = os.getenv("SCAMCHECK_ENGINE", "auto").lower()
    has_key = bool(os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_AUTH_TOKEN"))
    if choice == "claude" or (choice == "auto" and has_key):
        return "claude", ScamCheckAgent
    return "rules", RulesAgent


def create_app(
    agent_factory: Callable[[], Any] | None = None,
    rate_limit: tuple[int, float] = RATE_LIMIT,
) -> FastAPI:
    if agent_factory is None:
        engine, agent_factory = default_engine()
    else:
        engine = getattr(agent_factory, "engine", "claude")
    app = FastAPI(title="Scam Checker Agent API", version=__version__)
    app.state.engine = engine
    origins = [
        o.strip()
        for o in os.getenv(
            "SCAMCHECK_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"
        ).split(",")
    ]
    app.add_middleware(
        CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST"], allow_headers=["*"]
    )
    sessions = SessionStore()
    limiter = RateLimiter(*rate_limit)
    app.state.sessions = sessions

    def client_key(request: Request) -> str:
        # Behind a proxy (Render/Fly), the first X-Forwarded-For hop is the client.
        fwd = request.headers.get("x-forwarded-for")
        if fwd and os.getenv("SCAMCHECK_TRUST_PROXY") == "1":
            return fwd.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def check_rate(request: Request) -> None:
        if not limiter.allow(client_key(request)):
            raise HTTPException(
                status_code=429, detail="Too many requests, try again in a few minutes."
            )

    headers = {"Cache-Control": "no-store", "X-Accel-Buffering": "no"}

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "engine": engine,
            "sessions": len(sessions),
        }

    @app.post("/api/check")
    def check(body: CheckRequest, request: Request) -> StreamingResponse:
        check_rate(request)
        agent = agent_factory()
        sid, session = sessions.create(agent)
        first = {"type": "session", "session_id": sid, "engine": engine}
        return StreamingResponse(
            _stream(agent.check(body.message), session, first),
            media_type="text/event-stream",
            headers=headers,
        )

    @app.post("/api/ask")
    def ask(body: AskRequest, request: Request) -> StreamingResponse:
        check_rate(request)
        session = sessions.get(body.session_id)
        if session is None:
            raise HTTPException(
                status_code=404, detail="Session expired. Check the message again."
            )
        if session.follow_ups >= MAX_FOLLOW_UPS:
            raise HTTPException(
                status_code=429, detail="Follow-up limit reached for this session."
            )
        session.follow_ups += 1
        return StreamingResponse(
            _stream(session.agent.ask(body.question), session, None),
            media_type="text/event-stream",
            headers=headers,
        )

    return app


def __getattr__(name: str) -> Any:
    # `uvicorn scamcheck.api:app` builds the real app lazily, so importing this module in tests
    # never constructs an Anthropic client.
    if name == "app":
        return create_app()
    raise AttributeError(name)
