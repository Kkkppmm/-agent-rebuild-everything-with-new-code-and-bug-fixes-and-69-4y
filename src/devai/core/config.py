"""Configuration for DevAI clients and agents."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class DevAIConfig:
  """Central configuration for DevAI components."""

  api_key: str = ""
  base_url: str = "https://api.openai.com/v1"
  model: str = "gpt-4o-mini"
  temperature: float = 0.7
  max_tokens: int = 4096
  timeout: float = 60.0
  max_retries: int = 3
  extra_headers: dict[str, str] = field(default_factory=dict)

  @classmethod
  def from_env(cls, prefix: str = "DEVAI") -> DevAIConfig:
    """Load configuration from environment variables."""
    return cls(
      api_key=os.getenv(f"{prefix}_API_KEY", os.getenv("OPENAI_API_KEY", "")),
      base_url=os.getenv(f"{prefix}_BASE_URL", "https://api.openai.com/v1"),
      model=os.getenv(f"{prefix}_MODEL", "gpt-4o-mini"),
      temperature=float(os.getenv(f"{prefix}_TEMPERATURE", "0.7")),
      max_tokens=int(os.getenv(f"{prefix}_MAX_TOKENS", "4096")),
      timeout=float(os.getenv(f"{prefix}_TIMEOUT", "60.0")),
    )

  def with_overrides(self, **kwargs) -> DevAIConfig:
    """Return a copy with selective field overrides."""
    data = {
      "api_key": self.api_key,
      "base_url": self.base_url,
      "model": self.model,
      "temperature": self.temperature,
      "max_tokens": self.max_tokens,
      "timeout": self.timeout,
      "max_retries": self.max_retries,
      "extra_headers": dict(self.extra_headers),
    }
    data.update(kwargs)
    return DevAIConfig(**data)
