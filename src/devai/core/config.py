"""Configuration for DevAI clients."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class DevAIConfig:
    """Configuration for LLM and embedding clients."""

    api_key: str = ""
    model: str = "gpt-4o-mini"
    embedding_model: str = "text-embedding-3-small"
    base_url: str = "https://api.openai.com/v1"
    max_tokens: int = 4096
    temperature: float = 0.2
    timeout: float = 60.0
    max_retries: int = 3
    retry_delay: float = 1.0
    extra_headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> DevAIConfig:
        return cls(
            api_key=os.environ.get("DEVAI_API_KEY", os.environ.get("OPENAI_API_KEY", "")),
            model=os.environ.get("DEVAI_MODEL", "gpt-4o-mini"),
            embedding_model=os.environ.get("DEVAI_EMBEDDING_MODEL", "text-embedding-3-small"),
            base_url=os.environ.get("DEVAI_BASE_URL", "https://api.openai.com/v1"),
        )

    @classmethod
    def mock(cls) -> DevAIConfig:
        return cls(api_key="mock-key", model="mock-model")
