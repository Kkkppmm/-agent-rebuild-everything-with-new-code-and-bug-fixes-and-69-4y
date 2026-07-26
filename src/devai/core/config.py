"""Configuration for DevAI clients and agents."""

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DevAIConfig:
    api_key: Optional[str] = None
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    temperature: float = 0.7
    max_tokens: Optional[int] = None
    timeout: float = 60.0
    max_retries: int = 3
    retry_delay: float = 1.0

    def __post_init__(self) -> None:
        if self.api_key is None:
            self.api_key = os.environ.get("OPENAI_API_KEY")

    def with_overrides(self, **kwargs) -> "DevAIConfig":
        data = {
            "api_key": self.api_key,
            "base_url": self.base_url,
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "retry_delay": self.retry_delay,
        }
        data.update(kwargs)
        return DevAIConfig(**data)
