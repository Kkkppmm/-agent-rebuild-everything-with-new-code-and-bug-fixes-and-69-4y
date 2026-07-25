"""Configuration helpers for DevAI."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(key: str, default: str | None = None) -> str | None:
    return os.environ.get(key, default)


@dataclass
class DevAIConfig:
    """Runtime configuration loaded from environment variables or explicit values."""

    provider: str = "openai"
    api_key: str | None = None
    base_url: str | None = None
    model: str | None = None
    timeout: float = 60.0
    max_retries: int = 2
    extra_headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls, provider: str | None = None) -> DevAIConfig:
        provider = (provider or _env("DEVAI_PROVIDER", "openai")).lower()
        key_map = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "ollama": None,
        }
        model_map = {
            "openai": _env("DEVAI_MODEL", "gpt-4o-mini"),
            "anthropic": _env("DEVAI_MODEL", "claude-3-5-haiku-latest"),
            "ollama": _env("DEVAI_MODEL", "llama3.2"),
        }
        base_url_map = {
            "openai": _env("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            "anthropic": _env("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1"),
            "ollama": _env("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
        }
        env_key = key_map.get(provider)
        api_key = _env(env_key) if env_key else None
        if api_key is None:
            api_key = _env("DEVAI_API_KEY")

        return cls(
            provider=provider,
            api_key=api_key,
            base_url=base_url_map.get(provider),
            model=model_map.get(provider),
            timeout=float(_env("DEVAI_TIMEOUT", "60")),
            max_retries=int(_env("DEVAI_MAX_RETRIES", "2")),
        )

    def resolve_model(self, model: str | None) -> str:
        resolved = model or self.model
        if not resolved:
            raise ValueError("No model specified. Pass model= or set DEVAI_MODEL.")
        return resolved
