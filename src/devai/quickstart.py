"""One-line helpers to get started with DevAI."""

from __future__ import annotations

from typing import Any

from devai.assistant import CodeAssistant
from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.runtime import DevRuntime


def quickstart(
    *,
    provider: str = "openai",
    use_mock: bool = False,
    project_path: str | None = None,
    **kwargs: Any,
) -> DevRuntime:
    """Create a ready-to-use :class:`DevRuntime` in one call."""
    return DevRuntime.create(
        provider=provider,
        use_mock=use_mock,
        project_path=project_path,
        **kwargs,
    )


def assistant(
    *,
    provider: str = "openai",
    use_mock: bool = False,
    model: str | None = None,
    api_key: str | None = None,
    **kwargs: Any,
) -> CodeAssistant:
    """Create a :class:`CodeAssistant` in one call."""
    if use_mock or provider.lower() == "mock":
        return CodeAssistant(client=MockLLMClient())
    config = DevAIConfig.from_provider(provider, model=model, api_key=api_key, **kwargs)
    return CodeAssistant(client=LLMClient(config), config=config)
