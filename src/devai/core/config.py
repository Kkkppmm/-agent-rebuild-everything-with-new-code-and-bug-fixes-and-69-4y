"""Configuration for DevAI."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class DevAIConfig:
    """Configuration for LLM clients and assistants."""

    api_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    base_url: str = field(
        default_factory=lambda: os.getenv("DEVAI_BASE_URL", "https://api.openai.com/v1")
    )
    model: str = field(default_factory=lambda: os.getenv("DEVAI_MODEL", "gpt-4o-mini"))
    embedding_model: str = field(
        default_factory=lambda: os.getenv("DEVAI_EMBEDDING_MODEL", "text-embedding-3-small")
    )
    max_tokens: int = 4096
    temperature: float = 0.2
    timeout: float = 60.0
    max_retries: int = 3
    retry_delay: float = 1.0

    def validate(self) -> None:
        if not self.api_key:
            raise ValueError(
                "API key is required. Set OPENAI_API_KEY or pass api_key to DevAIConfig."
            )
