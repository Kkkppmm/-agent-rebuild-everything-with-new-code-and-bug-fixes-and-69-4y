"""Configuration for DevAI clients and agents."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class DevAIConfig:
    """Runtime configuration for LLM clients and agents."""

    api_key: str | None = field(default_factory=lambda: os.getenv("DEVAI_API_KEY"))
    base_url: str = field(
        default_factory=lambda: os.getenv("DEVAI_BASE_URL", "https://api.openai.com/v1")
    )
    model: str = field(default_factory=lambda: os.getenv("DEVAI_MODEL", "gpt-4o-mini"))
    embedding_model: str = field(
        default_factory=lambda: os.getenv("DEVAI_EMBEDDING_MODEL", "text-embedding-3-small")
    )
    temperature: float = 0.2
    max_tokens: int = 4096
    timeout: float = 60.0
    max_retries: int = 3
    retry_delay: float = 1.0
    system_prompt: str | None = None

    def with_overrides(self, **kwargs: object) -> DevAIConfig:
        """Return a copy with selective field overrides."""
        data = {
            "api_key": self.api_key,
            "base_url": self.base_url,
            "model": self.model,
            "embedding_model": self.embedding_model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "retry_delay": self.retry_delay,
            "system_prompt": self.system_prompt,
        }
        data.update(kwargs)
        return DevAIConfig(**data)
