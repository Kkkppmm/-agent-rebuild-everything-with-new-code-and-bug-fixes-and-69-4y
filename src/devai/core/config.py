"""Configuration for DevAI."""

import os
from dataclasses import dataclass, field


@dataclass
class DevAIConfig:
    """Configuration for DevAI clients and agents."""

    api_key: str | None = None
    provider: str = "openai"
    model: str = "gpt-4o-mini"
    base_url: str | None = None
    temperature: float = 0.7
    max_tokens: int = 4096
    timeout: float = 60.0
    max_retries: int = 3
    extra: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.api_key is None:
            self.api_key = os.environ.get("DEVAI_API_KEY")
        env_provider = os.environ.get("DEVAI_PROVIDER")
        if env_provider:
            self.provider = env_provider
        env_model = os.environ.get("DEVAI_MODEL")
        if env_model:
            self.model = env_model
        env_base = os.environ.get("DEVAI_BASE_URL")
        if env_base:
            self.base_url = env_base

    @property
    def is_mock(self) -> bool:
        return self.provider == "mock"
