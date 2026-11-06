"""Runtime configuration from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_MODEL = "claude-opus-5-5"


@dataclass(frozen=True)
class Settings:
    model: str = field(default_factory=lambda: os.getenv("SCAMCHECK_MODEL", DEFAULT_MODEL))
    effort: str = field(default_factory=lambda: os.getenv("SCAMCHECK_EFFORT", "medium"))
    safe_browsing_key: str | None = field(
        default_factory=lambda: os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or None
    )
    http_timeout: float = 5.0
    max_agent_iterations: int = 12
    user_agent: str = "scamcheck/0.1 (+https://github.com/mshe0093/scam-checker-agent)"


def get_settings() -> Settings:
    return Settings()
