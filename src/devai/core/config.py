"""Configuration for DevAI clients."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from devai.core.exceptions import ConfigError


@dataclass
class DevAIConfig:
    """Central configuration for DevAI LLM clients."""

    api_key: str | None = None
    model: str = "gpt-4o-mini"
    embedding_model: str = "text-embedding-3-small"
    base_url: str = "https://api.openai.com/v1"
    max_retries: int = 3
    timeout: float = 60.0
    temperature: float = 0.7
    max_tokens: int | None = None
    extra_headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> DevAIConfig:
        """Load configuration from environment variables."""
        return cls(
            api_key=os.environ.get("OPENAI_API_KEY"),
            model=os.environ.get("DEVAI_MODEL", "gpt-4o-mini"),
            embedding_model=os.environ.get("DEVAI_EMBEDDING_MODEL", "text-embedding-3-small"),
            base_url=os.environ.get("DEVAI_BASE_URL", "https://api.openai.com/v1"),
            max_retries=int(os.environ.get("DEVAI_MAX_RETRIES", "3")),
            timeout=float(os.environ.get("DEVAI_TIMEOUT", "60")),
        )

    def validate(self) -> None:
        """Validate that required fields are set."""
        if not self.api_key:
            raise ConfigError(
                "API key is required. Set OPENAI_API_KEY or pass api_key to DevAIConfig."
            )
