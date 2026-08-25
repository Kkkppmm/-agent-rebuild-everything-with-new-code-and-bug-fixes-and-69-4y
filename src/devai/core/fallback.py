"""Multi-provider fallback for resilient LLM calls."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from typing import Any

from devai.core.exceptions import LLMError
from devai.core.models import Message, Tool


@dataclass
class FallbackAttempt:
    """Record of a single fallback attempt."""

    index: int
    label: str
    error: str | None = None


@dataclass
class FallbackLLMClient:
    """Try multiple LLM clients in order until one succeeds.

    Useful for multi-provider setups (e.g. OpenAI primary, Ollama fallback)
    or model failover within the same provider.
    """

    clients: list[Any]
    labels: list[str] = field(default_factory=list)
    last_success_index: int | None = field(default=None, init=False)
    attempts: list[FallbackAttempt] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        if not self.clients:
            raise ValueError("FallbackLLMClient requires at least one client")
        if not self.labels:
            self.labels = [f"client-{index}" for index in range(len(self.clients))]
        if len(self.labels) != len(self.clients):
            raise ValueError("labels length must match clients length")

    def _record_attempt(self, index: int, error: str | None) -> None:
        self.attempts.append(FallbackAttempt(index=index, label=self.labels[index], error=error))

    def _raise_all_failed(self) -> None:
        details = "; ".join(
            f"{attempt.label}: {attempt.error or 'unknown'}" for attempt in self.attempts
        )
        raise LLMError(f"All {len(self.clients)} LLM clients failed: {details}")

    def complete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        self.attempts.clear()
        for index, client in enumerate(self.clients):
            try:
                response = client.complete(
                    messages,
                    tools=tools,
                    json_mode=json_mode,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                self.last_success_index = index
                self._record_attempt(index, None)
                return response
            except Exception as exc:
                self._record_attempt(index, str(exc))
        self._raise_all_failed()

    def stream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> Iterator[str]:
        self.attempts.clear()
        for index, client in enumerate(self.clients):
            try:
                chunks = list(
                    client.stream(messages, temperature=temperature, max_tokens=max_tokens)
                )
                self.last_success_index = index
                self._record_attempt(index, None)
                yield from chunks
                return
            except Exception as exc:
                self._record_attempt(index, str(exc))
        self._raise_all_failed()

    async def acomplete(
        self,
        messages: list[Message],
        *,
        tools: list[Tool] | None = None,
        json_mode: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        self.attempts.clear()
        for index, client in enumerate(self.clients):
            try:
                response = await client.acomplete(
                    messages,
                    tools=tools,
                    json_mode=json_mode,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                self.last_success_index = index
                self._record_attempt(index, None)
                return response
            except Exception as exc:
                self._record_attempt(index, str(exc))
        self._raise_all_failed()

    async def astream(
        self,
        messages: list[Message],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        self.attempts.clear()
        for index, client in enumerate(self.clients):
            try:
                async for chunk in client.astream(
                    messages, temperature=temperature, max_tokens=max_tokens
                ):
                    yield chunk
                self.last_success_index = index
                self._record_attempt(index, None)
                return
            except Exception as exc:
                self._record_attempt(index, str(exc))
        self._raise_all_failed()
