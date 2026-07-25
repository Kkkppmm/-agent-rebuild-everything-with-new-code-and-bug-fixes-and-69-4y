"""Abstract base provider and provider registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import AsyncIterator

from devai.types import (
  ChatResponse,
  EmbeddingResponse,
  Message,
  ProviderConfig,
  StreamChunk,
  ToolDefinition,
)


class BaseProvider(ABC):
  """Abstract interface for LLM providers."""

  def __init__(self, config: ProviderConfig):
    self.config = config

  @abstractmethod
  async def chat(
    self,
    messages: list[Message],
    model: str | None = None,
    tools: list[ToolDefinition] | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
  ) -> ChatResponse:
    ...

  @abstractmethod
  async def stream(
    self,
    messages: list[Message],
    model: str | None = None,
    tools: list[ToolDefinition] | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
  ) -> AsyncIterator[StreamChunk]:
    ...

  @abstractmethod
  async def embed(
    self,
    texts: list[str],
    model: str | None = None,
  ) -> EmbeddingResponse:
    ...
