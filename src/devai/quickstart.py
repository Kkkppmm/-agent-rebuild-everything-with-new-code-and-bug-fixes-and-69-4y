"""Quick-start helpers for DevAI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from devai.assistant import CodeAssistant
from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.runtime import DevRuntime


def quickstart(
    *,
    provider: str = "openai",
    model: str | None = None,
    api_key: str | None = None,
    project_path: str | Path | None = None,
    use_mock: bool = False,
    **kwargs: Any,
) -> DevRuntime:
    """Bootstrap DevAI in one call.

    Returns a fully wired :class:`DevRuntime` with assistant, kit, and programs.

    Example::

        from devai import quickstart

        runtime = quickstart(use_mock=True)
        print(runtime.review("def add(a, b): return a + b"))
    """
    return DevRuntime.create(
        provider=provider,
        model=model,
        api_key=api_key,
        project_path=project_path,
        use_mock=use_mock,
        **kwargs,
    )


def assistant(
    *,
    provider: str = "openai",
    model: str | None = None,
    api_key: str | None = None,
    use_mock: bool = False,
    **kwargs: Any,
) -> CodeAssistant:
    """Create a :class:`CodeAssistant` with minimal setup."""
    if use_mock or provider.lower() == "mock":
        return CodeAssistant(client=MockLLMClient())
    config = DevAIConfig.from_provider(provider, model=model, api_key=api_key, **kwargs)
    return CodeAssistant(client=LLMClient(config))
