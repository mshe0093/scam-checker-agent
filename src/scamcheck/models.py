"""Shared result types. Every tool returns a ToolResult so the agent, UI and tests see one shape."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Status(StrEnum):
    OK = "ok"
    UNVERIFIED = "unverified"  # the check could not be completed; NOT evidence either way
    ERROR = "error"


class Severity(StrEnum):
    RED = "red"  # strong scam indicator
    AMBER = "amber"  # suspicious, needs context
    GREEN = "green"  # points toward legitimacy
    INFO = "info"  # neutral fact


class Signal(BaseModel):
    id: str
    severity: Severity
    detail: str
    # Deterministic signals come from hard facts (registry data, exact dataset matches), not heuristics.
    # Only deterministic red signals can trigger the verdict floor.
    deterministic: bool = False


class ToolResult(BaseModel):
    tool: str
    status: Status
    summary: str
    signals: list[Signal] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    sources: list[str] = Field(default_factory=list)

    def for_model(self) -> str:
        """Compact JSON the model reads as the tool_result content."""
        return self.model_dump_json(exclude_none=True)

    @property
    def hard_red_flags(self) -> list[Signal]:
        return [s for s in self.signals if s.severity is Severity.RED and s.deterministic]
