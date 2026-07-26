"""Configuration for DevAI clients."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class DevAIConfig:
    """Configuration for LLM and embedding clients."""

    api_key: str | None = None
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    embedding_model: str = "text-embedding-3-small"
    temperature: float = 0.7
    max_tokens: int = 4096
    timeout: float = 60.0
    max_retries: int = 3
    retry_delay: float = 1.0
    extra_headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.api_key is None:
            self.api_key = os.environ.get("OPENAI_API_KEY")

    @classmethod
    def from_env(cls, **overrides: object) -> DevAIConfig:
        """Create config from environment variables with optional overrides."""
        return cls(
            api_key=os.environ.get("OPENAI_API_KEY"),
            base_url=os.environ.get("DEVAI_BASE_URL", "https://api.openai.com/v1"),
            model=os.environ.get("DEVAI_MODEL", "gpt-4o-mini"),
            embedding_model=os.environ.get(
                "DEVAI_EMBEDDING_MODEL", "text-embedding-3-small"
            ),
            **overrides,  # type: ignore[arg-type]
        )
