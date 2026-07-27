"""DevAI configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from devai.core.exceptions import ConfigurationError


@dataclass
class DevAIConfig:
    """Configuration for DevAI clients and agents."""

    api_key: str | None = None
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    embedding_model: str = "text-embedding-3-small"
    max_tokens: int = 4096
    temperature: float = 0.2
    timeout: float = 60.0
    max_retries: int = 3
    retry_delay: float = 1.0
    extra_headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.api_key is None:
            self.api_key = os.environ.get("DEVAI_API_KEY")
        env_base = os.environ.get("DEVAI_BASE_URL")
        if env_base:
            self.base_url = env_base
        env_model = os.environ.get("DEVAI_MODEL")
        if env_model:
            self.model = env_model
        env_max = os.environ.get("DEVAI_MAX_TOKENS")
        if env_max:
            self.max_tokens = int(env_max)
        env_temp = os.environ.get("DEVAI_TEMPERATURE")
        if env_temp:
            self.temperature = float(env_temp)

    def validate(self) -> None:
        """Raise ConfigurationError if required settings are missing."""
        if not self.api_key:
            raise ConfigurationError(
                "API key is required. Set DEVAI_API_KEY or pass api_key to DevAIConfig."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url,
            "model": self.model,
            "embedding_model": self.embedding_model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
        }
