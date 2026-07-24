"""Configuration for DevAI."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from devai.core.exceptions import ConfigError


@dataclass
class DevAIConfig:
    """Central configuration for DevAI clients and agents."""

    api_key: str | None = None
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    embedding_model: str = "text-embedding-3-small"
    temperature: float = 0.7
    max_tokens: int | None = None
    timeout: float = 60.0
    max_retries: int = 3
    retry_delay: float = 1.0

    @classmethod
    def from_env(cls, prefix: str = "DEVAI") -> DevAIConfig:
        return cls(
            api_key=os.environ.get(f"{prefix}_API_KEY") or os.environ.get("OPENAI_API_KEY"),
            base_url=os.environ.get(f"{prefix}_BASE_URL", "https://api.openai.com/v1"),
            model=os.environ.get(f"{prefix}_MODEL", "gpt-4o-mini"),
            embedding_model=os.environ.get(
                f"{prefix}_EMBEDDING_MODEL", "text-embedding-3-small"
            ),
            temperature=float(os.environ.get(f"{prefix}_TEMPERATURE", "0.7")),
            max_tokens=int(os.environ[f"{prefix}_MAX_TOKENS"])
            if os.environ.get(f"{prefix}_MAX_TOKENS")
            else None,
            timeout=float(os.environ.get(f"{prefix}_TIMEOUT", "60.0")),
            max_retries=int(os.environ.get(f"{prefix}_MAX_RETRIES", "3")),
        )

    def require_api_key(self) -> str:
        if not self.api_key:
            raise ConfigError(
                "API key is required. Set DEVAI_API_KEY or OPENAI_API_KEY environment variable."
            )
        return self.api_key
