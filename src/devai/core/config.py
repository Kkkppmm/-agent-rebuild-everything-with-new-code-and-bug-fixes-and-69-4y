"""Configuration for DevAI."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DevAIConfig:
    """Configuration for LLM clients and DevAI components."""

    api_key: str | None = None
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    temperature: float = 0.2
    max_tokens: int = 4096
    timeout: float = 60.0
    max_retries: int = 3
    retry_delay: float = 1.0
    extra_headers: dict[str, str] = field(default_factory=dict)
    extra_body: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.api_key is None:
            self.api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("DEVAI_API_KEY")

    @classmethod
    def from_env(cls, **overrides: Any) -> DevAIConfig:
        """Create config from environment variables with optional overrides."""
        return cls(
            api_key=overrides.get("api_key", os.environ.get("OPENAI_API_KEY")),
            base_url=overrides.get("base_url", os.environ.get("DEVAI_BASE_URL", "https://api.openai.com/v1")),
            model=overrides.get("model", os.environ.get("DEVAI_MODEL", "gpt-4o-mini")),
            temperature=float(overrides.get("temperature", os.environ.get("DEVAI_TEMPERATURE", "0.2"))),
            max_tokens=int(overrides.get("max_tokens", os.environ.get("DEVAI_MAX_TOKENS", "4096"))),
            timeout=float(overrides.get("timeout", os.environ.get("DEVAI_TIMEOUT", "60.0"))),
            max_retries=int(overrides.get("max_retries", os.environ.get("DEVAI_MAX_RETRIES", "3"))),
        )
