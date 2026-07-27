"""Configuration for DevAI."""

from __future__ import annotations

import os
from typing import Literal

from pydantic import BaseModel, Field

from devai.core.exceptions import ConfigurationError

ProviderType = Literal["openai", "anthropic", "mock"]


class DevAIConfig(BaseModel):
  provider: ProviderType = "openai"
  model: str = "gpt-4o-mini"
  api_key: str | None = None
  base_url: str | None = None
  max_tokens: int = Field(default=4096, ge=1)
  temperature: float = Field(default=0.2, ge=0.0, le=2.0)
  timeout: float = Field(default=60.0, ge=1.0)
  max_retries: int = Field(default=3, ge=0)
  system_prompt: str | None = None

  @classmethod
  def from_env(cls) -> DevAIConfig:
    return cls(
      provider=os.getenv("DEVAI_PROVIDER", "openai"),  # type: ignore[arg-type]
      model=os.getenv("DEVAI_MODEL", "gpt-4o-mini"),
      api_key=os.getenv("DEVAI_API_KEY"),
      base_url=os.getenv("DEVAI_BASE_URL"),
      max_tokens=int(os.getenv("DEVAI_MAX_TOKENS", "4096")),
      temperature=float(os.getenv("DEVAI_TEMPERATURE", "0.2")),
    )

  def validate_provider(self) -> None:
    if self.provider == "mock":
      return
    if not self.api_key:
      raise ConfigurationError(
        f"API key required for provider '{self.provider}'. "
        "Set DEVAI_API_KEY or pass api_key to DevAIConfig."
      )

  @property
  def effective_base_url(self) -> str:
    if self.base_url:
      return self.base_url
    if self.provider == "openai":
      return "https://api.openai.com/v1"
    if self.provider == "anthropic":
      return "https://api.anthropic.com/v1"
    return ""
