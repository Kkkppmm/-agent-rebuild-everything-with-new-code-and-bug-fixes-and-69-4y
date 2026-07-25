"""Configuration for DevAI clients and agents."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class DevAIConfig:
    """Runtime configuration for LLM interactions."""

    api_key: str | None = None
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    embedding_model: str = "text-embedding-3-small"
    temperature: float = 0.7
    max_tokens: int | None = None
    timeout: float = 60.0
    max_tool_rounds: int = 10
    max_retries: int = 3
    retry_backoff: float = 1.0
    extra_headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.api_key is None:
            self.api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("DEVAI_API_KEY")

    @classmethod
    def from_env(cls, prefix: str = "DEVAI") -> DevAIConfig:
        """Build config from environment variables (e.g. DEVAI_MODEL)."""
        return cls(
            api_key=os.environ.get(f"{prefix}_API_KEY") or os.environ.get("OPENAI_API_KEY"),
            base_url=os.environ.get(f"{prefix}_BASE_URL", "https://api.openai.com/v1"),
            model=os.environ.get(f"{prefix}_MODEL", "gpt-4o-mini"),
            embedding_model=os.environ.get(f"{prefix}_EMBEDDING_MODEL", "text-embedding-3-small"),
            temperature=float(os.environ.get(f"{prefix}_TEMPERATURE", "0.7")),
            max_tokens=int(os.environ[f"{prefix}_MAX_TOKENS"])
            if os.environ.get(f"{prefix}_MAX_TOKENS")
            else None,
            timeout=float(os.environ.get(f"{prefix}_TIMEOUT", "60.0")),
            max_retries=int(os.environ.get(f"{prefix}_MAX_RETRIES", "3")),
        )
