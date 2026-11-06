"""The agent: a hand-written Claude tool-use loop that emits a trace of every step.

Why a manual loop rather than the SDK tool runner: we stream each tool call/result to the UI as it
happens, run independent tool calls in parallel, and apply a deterministic verdict floor after the
model decides, none of which should be hidden inside a helper.
"""

from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import anthropic

from scamcheck.config import Settings, get_settings
from scamcheck.models import ToolResult
from scamcheck.prompts import SYSTEM_PROMPT, wrap_message
from scamcheck.registry import anthropic_tools, run_tool

Event = dict[str, Any]
FALLBACK_BETA = "server-side-fallback-2026-07-01"
NUDGE = (
    "Please call submit_verdict now with your final assessment, based only on the tool results."
)


def apply_verdict_floor(verdict: dict[str, Any], results: list[ToolResult]) -> dict[str, Any]:
    """Hard, deterministic red flags (impersonation domain, Safe Browsing hit, domain under 30 days
    old...) cannot be overruled into 'likely_legitimate' by the model."""
    hard = [s for r in results for s in r.hard_red_flags]
    if verdict.get("verdict") == "likely_legitimate" and hard:
        verdict = {
            **verdict,
            "verdict": "suspicious",
            "confidence": "low",
            "floor_applied": {
                "from": "likely_legitimate",
                "reasons": [f"{s.id}: {s.detail}" for s in hard],
            },
        }
    return verdict


class ScamCheckAgent:
    def __init__(
        self, client: anthropic.Anthropic | None = None, settings: Settings | None = None
    ) -> None:
        self.settings = settings or get_settings()
        self.client = client or anthropic.Anthropic()
        self.messages: list[dict[str, Any]] = []
        self.results: list[ToolResult] = []
        self.verdict: dict[str, Any] | None = None
        self.usage = {"input_tokens": 0, "output_tokens": 0, "model_calls": 0, "tool_calls": 0}

    # ---- public API -------------------------------------------------------------------------
    def check(self, message: str) -> Iterator[Event]:
        """Investigate a suspicious message. Yields trace events; the last is 'verdict' or 'error'."""
        self.messages = [{"role": "user", "content": wrap_message(message)}]
        self.results, self.verdict = [], None
        yield from self._loop(require_verdict=True)

    def ask(self, question: str) -> Iterator[Event]:
        """Follow-up question in the same session (tools stay available)."""
        self._append_user([{"type": "text", "text": question}])
        yield from self._loop(require_verdict=False)

    # ---- internals --------------------------------------------------------------------------
    def _append_user(self, blocks: list[dict[str, Any]]) -> None:
        last = self.messages[-1] if self.messages else None
        if last and last["role"] == "user" and isinstance(last["content"], list):
            last["content"].extend(blocks)  # merge: keeps strict user/assistant alternation
        else:
            self.messages.append({"role": "user", "content": blocks})

    def _call_model(self) -> Any:
        self.usage["model_calls"] += 1
        return self.client.beta.messages.create(
            model=self.settings.model,
            max_tokens=16000,
            system=SYSTEM_PROMPT,
            tools=anthropic_tools(),
            messages=self.messages,
            thinking={"type": "adaptive"},
            output_config={"effort": self.settings.effort},
            betas=[FALLBACK_BETA],
            fallbacks="default",
        )

    def _loop(self, require_verdict: bool) -> Iterator[Event]:
        nudged = False
        for _ in range(self.settings.max_agent_iterations):
            try:
                response = self._call_model()
            except anthropic.APIStatusError as exc:
                yield {
                    "type": "error",
                    "message": f"Claude API error {exc.status_code}: {exc.message}",
                }
                return
            except anthropic.APIConnectionError:
                yield {"type": "error", "message": "Could not reach the Claude API."}
                return
            self.usage["input_tokens"] += response.usage.input_tokens
            self.usage["output_tokens"] += response.usage.output_tokens

            if response.stop_reason == "refusal":
                yield {"type": "error", "message": "The model declined to process this message."}
                return
            self.messages.append({"role": "assistant", "content": response.content})

            for block in response.content:
                if block.type == "text" and block.text.strip():
                    yield {"type": "text", "text": block.text}

            tool_uses = [b for b in response.content if b.type == "tool_use"]
            if not tool_uses:
                if require_verdict and self.verdict is None and not nudged:
                    nudged = True
                    self._append_user([{"type": "text", "text": NUDGE}])
                    continue
                if require_verdict and self.verdict is None:
                    yield self._fallback_verdict()
                yield {"type": "done", "usage": dict(self.usage)}
                return

            work = [b for b in tool_uses if b.name != "submit_verdict"]
            for b in work:
                yield {"type": "tool_call", "id": b.id, "name": b.name, "input": b.input}
            self.usage["tool_calls"] += len(work)
            with ThreadPoolExecutor(max_workers=6) as pool:
                outcomes = list(pool.map(lambda b: run_tool(b.name, dict(b.input)), work))

            tool_results: list[dict[str, Any]] = []
            for b, res in zip(work, outcomes, strict=True):
                self.results.append(res)
                yield {
                    "type": "tool_result",
                    "id": b.id,
                    "name": b.name,
                    "result": res.model_dump(),
                }
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": b.id,
                        "content": res.for_model(),
                        **({"is_error": True} if res.status == "error" else {}),
                    }
                )

            verdict_block = next((b for b in tool_uses if b.name == "submit_verdict"), None)
            if verdict_block is not None:
                self.verdict = apply_verdict_floor(dict(verdict_block.input), self.results)
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": verdict_block.id,
                        "content": "Verdict recorded and shown to the user.",
                    }
                )
                self._append_user(tool_results)
                yield {"type": "verdict", "verdict": self.verdict}
                yield {"type": "done", "usage": dict(self.usage)}
                return
            self._append_user(tool_results)

        yield {"type": "error", "message": "Stopped: too many agent iterations."}
        if require_verdict and self.verdict is None:
            yield self._fallback_verdict()

    def _fallback_verdict(self) -> Event:
        self.verdict = apply_verdict_floor(
            {
                "verdict": "insufficient_information",
                "confidence": "low",
                "category": "other",
                "headline": "The agent did not reach a verdict. Treat the message with caution.",
                "findings": [],
                "recommended_actions": [
                    "Do not click links or share TAC/OTP codes.",
                    "Contact the organisation through its official website or app.",
                ],
            },
            self.results,
        )
        return {"type": "verdict", "verdict": self.verdict}
