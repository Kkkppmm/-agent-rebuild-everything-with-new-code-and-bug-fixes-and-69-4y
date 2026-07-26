"""Configuration for DevAI."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class DevAIConfig:
    """Central configuration for DevAI clients and agents."""

    api_key: str | None = None
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    embedding_model: str = "text-embedding-3-small"
    temperature: float = 0.7
    max_tokens: int = 4096
    timeout: float = 60.0
    max_retries: int = 3
    retry_delay: float = 1.0

    @classmethod
    def from_env(cls, prefix: str = "DEVAI") -> DevAIConfig:
        """Load configuration from environment variables."""
        return cls(
            api_key=os.getenv(f"{prefix}_API_KEY") or os.getenv("OPENAI_API_KEY"),
            base_url=os.getenv(f"{prefix}_BASE_URL", "https://api.openai.com/v1"),
            model=os.getenv(f"{prefix}_MODEL", "gpt-4o-mini"),
            embedding_model=os.getenv(
                f"{prefix}_EMBEDDING_MODEL", "text-embedding-3-small"
            ),
            temperature=float(os.getenv(f"{prefix}_TEMPERATURE", "0.7")),
            max_tokens=int(os.getenv(f"{prefix}_MAX_TOKENS", "4096")),
            timeout=float(os.getenv(f"{prefix}_TIMEOUT", "60.0")),
            max_retries=int(os.getenv(f"{prefix}_MAX_RETRIES", "3")),
            retry_delay=float(os.getenv(f"{prefix}_RETRY_DELAY", "1.0")),
        )

    def with_overrides(self, **kwargs) -> DevAIConfig:
        """Return a copy with overridden fields."""
        data = {**self.__dict__, **kwargs}
        return DevAIConfig(**data)
