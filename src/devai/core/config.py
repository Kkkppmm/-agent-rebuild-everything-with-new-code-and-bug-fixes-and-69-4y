"""Configuration for DevAI clients."""


from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class DevAIConfig:
    api_key: str | None = None
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    embedding_model: str = "text-embedding-3-small"
    temperature: float = 0.7
    max_tokens: int | None = None
    timeout: float = 60.0
    max_retries: int = 3
    retry_delay: float = 1.0

    def __post_init__(self) -> None:
        if self.api_key is None:
            self.api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("DEVAI_API_KEY")

    @classmethod
    def from_env(cls, **overrides: object) -> DevAIConfig:
        return cls(
            api_key=os.environ.get("OPENAI_API_KEY") or os.environ.get("DEVAI_API_KEY"),
            base_url=os.environ.get("DEVAI_BASE_URL", "https://api.openai.com/v1"),
            model=os.environ.get("DEVAI_MODEL", "gpt-4o-mini"),
            embedding_model=os.environ.get(
                "DEVAI_EMBEDDING_MODEL", "text-embedding-3-small"
            ),
            **overrides,  # type: ignore[arg-type]
        )
