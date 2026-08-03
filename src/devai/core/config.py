"""Configuration for DevAI."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from devai.core.exceptions import ConfigError


@dataclass
class DevAIConfig:
    """Configuration for LLM clients and assistants."""

    api_key: str | None = None
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    max_tokens: int = 4096
    temperature: float = 0.2
    timeout: float = 60.0
    max_retries: int = 3
    retry_delay: float = 1.0
    extra_headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.api_key is None:
            self.api_key = os.environ.get("DEVAI_API_KEY")
        env_base = os.environ.get("DEVAI_BASE_URL")
        if env_base:
            self.base_url = env_base
        env_model = os.environ.get("DEVAI_MODEL")
        if env_model:
            self.model = env_model
        if max_tokens_env := os.environ.get("DEVAI_MAX_TOKENS"):
            self.max_tokens = int(max_tokens_env)
        if temp_env := os.environ.get("DEVAI_TEMPERATURE"):
            self.temperature = float(temp_env)

    def validate(self) -> None:
        """Validate that required configuration is present."""
        if not self.api_key:
            raise ConfigError(
                "API key is required. Set DEVAI_API_KEY or pass api_key to DevAIConfig."
            )

    @classmethod
    def for_openai(
        cls,
        api_key: str | None = None,
        model: str = "gpt-4o-mini",
        **kwargs: Any,
    ) -> DevAIConfig:
        """Create config for the OpenAI API."""
        return cls(
            api_key=api_key,
            base_url="https://api.openai.com/v1",
            model=model,
            **kwargs,
        )

    @classmethod
    def for_ollama(
        cls,
        model: str = "llama3.2",
        base_url: str = "http://localhost:11434/v1",
        **kwargs: Any,
    ) -> DevAIConfig:
        """Create config for a local Ollama server (OpenAI-compatible endpoint)."""
        return cls(
            api_key="ollama",
            base_url=base_url,
            model=model,
            **kwargs,
        )

    @classmethod
    def from_env(cls, *, provider: str | None = None, **kwargs: Any) -> DevAIConfig:
        """Create configuration from ``DEVAI_*`` environment variables.

        Supported variables:
        - ``DEVAI_PROVIDER`` — ``openai``, ``ollama``, or ``mock`` (default: ``openai``)
        - ``DEVAI_API_KEY``, ``DEVAI_BASE_URL``, ``DEVAI_MODEL``
        - ``DEVAI_MAX_TOKENS``, ``DEVAI_TEMPERATURE``
        """
        prov = (provider or os.environ.get("DEVAI_PROVIDER", "openai")).lower().strip()
        if prov == "mock":
            return cls(
                api_key="mock",
                model=kwargs.pop("model", None) or os.environ.get("DEVAI_MODEL", "mock-model"),
                **kwargs,
            )
        return cls.from_provider(prov, **kwargs)

    @classmethod
    def from_provider(
        cls,
        provider: str,
        *,
        model: str | None = None,
        api_key: str | None = None,
        **kwargs: Any,
    ) -> DevAIConfig:
        """Create config from a named provider: openai, ollama, or mock."""
        normalized = provider.lower().strip()
        if normalized == "openai":
            return cls.for_openai(api_key=api_key, model=model or "gpt-4o-mini", **kwargs)
        if normalized == "ollama":
            return cls.for_ollama(model=model or "llama3.2", **kwargs)
        if normalized == "mock":
            return cls(api_key="mock", model=model or "mock-model", **kwargs)
        raise ConfigError(
            f"Unknown provider '{provider}'. Supported: openai, ollama, mock"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url,
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "retry_delay": self.retry_delay,
        }
