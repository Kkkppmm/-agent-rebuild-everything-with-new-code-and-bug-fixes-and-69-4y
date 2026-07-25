"""Configuration for DevAI clients."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class DevAIConfig:
  """Runtime configuration for LLM providers."""

  api_key: str | None = None
  base_url: str = "https://api.openai.com/v1"
  model: str = "gpt-4o-mini"
  temperature: float = 0.7
  max_tokens: int | None = None
  timeout: float = 60.0
  max_retries: int = 3
  default_headers: dict[str, str] = field(default_factory=dict)

  @classmethod
  def from_env(cls, prefix: str = "DEVAI") -> DevAIConfig:
    """Load configuration from environment variables."""
    return cls(
      api_key=os.getenv(f"{prefix}_API_KEY") or os.getenv("OPENAI_API_KEY"),
      base_url=os.getenv(f"{prefix}_BASE_URL", "https://api.openai.com/v1"),
      model=os.getenv(f"{prefix}_MODEL", "gpt-4o-mini"),
      temperature=float(os.getenv(f"{prefix}_TEMPERATURE", "0.7")),
      max_tokens=int(os.getenv(f"{prefix}_MAX_TOKENS"))
      if os.getenv(f"{prefix}_MAX_TOKENS")
      else None,
      timeout=float(os.getenv(f"{prefix}_TIMEOUT", "60.0")),
      max_retries=int(os.getenv(f"{prefix}_MAX_RETRIES", "3")),
    )

  def with_overrides(self, **kwargs) -> DevAIConfig:
    """Return a copy with selective overrides."""
    data = {
      "api_key": self.api_key,
      "base_url": self.base_url,
      "model": self.model,
      "temperature": self.temperature,
      "max_tokens": self.max_tokens,
      "timeout": self.timeout,
      "max_retries": self.max_retries,
      "default_headers": dict(self.default_headers),
    }
    data.update(kwargs)
    return DevAIConfig(**data)
