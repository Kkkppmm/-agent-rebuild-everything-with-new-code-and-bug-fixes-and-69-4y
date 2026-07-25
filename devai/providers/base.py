"""Provider protocol and base implementations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Iterator
from typing import Any

from devai.types import ChatResponse, Usage


class BaseProvider(ABC):
    """Abstract base for LLM providers."""

    @abstractmethod
    def chat(
        self,
        messages: list[dict[str, Any]],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> ChatResponse:
        """Send a chat completion request."""

    @abstractmethod
    async def chat_async(
        self,
        messages: list[dict[str, Any]],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> ChatResponse:
        """Async chat completion."""

    @abstractmethod
    def chat_stream(
        self,
        messages: list[dict[str, Any]],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> Iterator[str]:
        """Stream chat completion tokens."""

    @abstractmethod
    async def chat_stream_async(
        self,
        messages: list[dict[str, Any]],
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Async stream chat completion tokens."""

    @abstractmethod
    def embed(self, texts: list[str], model: str, **kwargs: Any) -> list[list[float]]:
        """Generate embeddings for texts."""

    @abstractmethod
    async def embed_async(
        self, texts: list[str], model: str, **kwargs: Any
    ) -> list[list[float]]:
        """Async embeddings."""
