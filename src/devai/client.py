"""Main DevAI client — unified interface for all providers."""

from __future__ import annotations

import os
from typing import AsyncIterator

from devai.exceptions import ConfigurationError
from devai.providers import (
  AnthropicProvider,
  BaseProvider,
  OllamaProvider,
  OpenAIProvider,
)
from devai.types import (
  ChatResponse,
  EmbeddingResponse,
  Message,
  ProviderConfig,
  StreamChunk,
  ToolDefinition,
)

PROVIDER_MAP = {
  "openai": OpenAIProvider,
  "anthropic": AnthropicProvider,
  "ollama": OllamaProvider,
}


class DevAI:
  """Unified AI client for developers.

  Example::

      client = DevAI(provider="openai", api_key="sk-...")
      response = await client.chat("Hello!")
      print(response.content)
  """

  def __init__(
    self,
    provider: str = "openai",
    api_key: str | None = None,
    base_url: str | None = None,
    model: str | None = None,
    timeout: float = 60.0,
    config: ProviderConfig | None = None,
  ):
    if config:
      self.config = config
      provider_name = provider
    else:
      resolved_key = api_key or os.environ.get("DEVAI_API_KEY") or os.environ.get("OPENAI_API_KEY")
      self.config = ProviderConfig(
        api_key=resolved_key,
        base_url=base_url,
        model=model,
        timeout=timeout,
      )
      provider_name = provider

    provider_cls = PROVIDER_MAP.get(provider_name.lower())
    if not provider_cls:
      raise ConfigurationError(
        f"Unknown provider: {provider_name}. Choose from: {', '.join(PROVIDER_MAP)}"
      )
    self.provider: BaseProvider = provider_cls(self.config)
    self._provider_name = provider_name.lower()

  @property
  def model(self) -> str | None:
    return self.config.model

  async def chat(
    self,
    prompt: str | list[Message],
    *,
    model: str | None = None,
    system: str | None = None,
    tools: list[ToolDefinition] | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
  ) -> ChatResponse:
    """Send a chat message and get a response.

    Args:
      prompt: A user message string or list of Message objects.
      model: Override the default model.
      system: Optional system prompt (prepended if prompt is a string).
      tools: Optional tool definitions for function calling.
      temperature: Sampling temperature.
      max_tokens: Maximum tokens in the response.
    """
    messages = self._build_messages(prompt, system)
    return await self.provider.chat(
      messages,
      model=model,
      tools=tools,
      temperature=temperature,
      max_tokens=max_tokens,
    )

  async def stream(
    self,
    prompt: str | list[Message],
    *,
    model: str | None = None,
    system: str | None = None,
    tools: list[ToolDefinition] | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
  ) -> AsyncIterator[StreamChunk]:
    """Stream a chat response token by token."""
    messages = self._build_messages(prompt, system)
    async for chunk in self.provider.stream(
      messages,
      model=model,
      tools=tools,
      temperature=temperature,
      max_tokens=max_tokens,
    ):
      yield chunk

  async def embed(
    self,
    texts: list[str] | str,
    *,
    model: str | None = None,
  ) -> EmbeddingResponse:
    """Generate embeddings for text(s)."""
    if isinstance(texts, str):
      texts = [texts]
    return await self.provider.embed(texts, model=model)

  def _build_messages(
    self,
    prompt: str | list[Message],
    system: str | None,
  ) -> list[Message]:
    if isinstance(prompt, list):
      return prompt
    messages: list[Message] = []
    if system:
      messages.append(Message(role="system", content=system))
    messages.append(Message(role="user", content=prompt))
    return messages
