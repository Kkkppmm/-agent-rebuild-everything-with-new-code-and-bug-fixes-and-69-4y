"""Configuration for DevAI."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class DevAIConfig:
    """Configuration for LLM clients and agents."""

    api_key: str | None = None
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    temperature: float = 0.7
    max_tokens: int | None = None
    timeout: float = 60.0
    max_retries: int = 3
    retry_delay: float = 1.0
    json_mode: bool = False
    extra_headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.api_key is None:
            self.api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("DEVAI_API_KEY")

    @classmethod
    def from_env(cls, prefix: str = "DEVAI") -> DevAIConfig:
        """Create config from environment variables with the given prefix."""
        return cls(
            api_key=os.environ.get(f"{prefix}_API_KEY") or os.environ.get("OPENAI_API_KEY"),
            base_url=os.environ.get(f"{prefix}_BASE_URL", "https://api.openai.com/v1"),
            model=os.environ.get(f"{prefix}_MODEL", "gpt-4o-mini"),
            temperature=float(os.environ.get(f"{prefix}_TEMPERATURE", "0.7")),
            max_tokens=int(os.environ[f"{prefix}_MAX_TOKENS"])
            if f"{prefix}_MAX_TOKENS" in os.environ
            else None,
            timeout=float(os.environ.get(f"{prefix}_TIMEOUT", "60.0")),
        )

    def with_overrides(self, **kwargs) -> DevAIConfig:
        """Return a copy with overridden fields."""
        from dataclasses import asdict

        data = asdict(self)
        data.update(kwargs)
        return DevAIConfig(**data)
