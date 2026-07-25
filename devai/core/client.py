"""OpenAI-compatible LLM client with streaming and tool support."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx

from devai.core.config import DevAIConfig
from devai.core.models import CompletionResult, Message, Role, ToolCall, ToolDefinition
from devai.utils.retry import retry_async, retry_sync


class LLMClient:
  """Unified client for OpenAI-compatible chat completion APIs."""

  def __init__(self, config: DevAIConfig | None = None) -> None:
    self.config = config or DevAIConfig.from_env()

  def _headers(self) -> dict[str, str]:
    headers = {"Content-Type": "application/json", **self.config.default_headers}
    if self.config.api_key:
      headers["Authorization"] = f"Bearer {self.config.api_key}"
    return headers

  def _build_payload(
    self,
    messages: list[Message],
    *,
    tools: list[ToolDefinition] | None = None,
    stream: bool = False,
    **overrides: Any,
  ) -> dict[str, Any]:
    payload: dict[str, Any] = {
      "model": overrides.pop("model", self.config.model),
      "messages": [message.to_api_dict() for message in messages],
      "temperature": overrides.pop("temperature", self.config.temperature),
      "stream": stream,
    }
    if self.config.max_tokens is not None:
      payload["max_tokens"] = overrides.pop("max_tokens", self.config.max_tokens)
    if tools:
      payload["tools"] = [tool.to_api_dict() for tool in tools]
    payload.update(overrides)
    return payload

  def _parse_response(self, data: dict[str, Any]) -> CompletionResult:
    choice = data.get("choices", [{}])[0]
    message = choice.get("message", {})
    tool_calls = [
      ToolCall.from_api_dict(call) for call in message.get("tool_calls") or []
    ]
    return CompletionResult(
      content=message.get("content"),
      tool_calls=tool_calls,
      finish_reason=choice.get("finish_reason"),
      usage=data.get("usage", {}),
      raw=data,
    )

  def complete(
    self,
    messages: list[Message],
    *,
    tools: list[ToolDefinition] | None = None,
    **kwargs: Any,
  ) -> CompletionResult:
    """Send a chat completion request synchronously."""
    payload = self._build_payload(messages, tools=tools, stream=False, **kwargs)

    def _request() -> CompletionResult:
      with httpx.Client(timeout=self.config.timeout) as client:
        response = client.post(
          f"{self.config.base_url.rstrip('/')}/chat/completions",
          headers=self._headers(),
          json=payload,
        )
        response.raise_for_status()
        return self._parse_response(response.json())

    return retry_sync(_request, max_attempts=self.config.max_retries)

  async def acomplete(
    self,
    messages: list[Message],
    *,
    tools: list[ToolDefinition] | None = None,
    **kwargs: Any,
  ) -> CompletionResult:
    """Send a chat completion request asynchronously."""
    payload = self._build_payload(messages, tools=tools, stream=False, **kwargs)

    async def _request() -> CompletionResult:
      async with httpx.AsyncClient(timeout=self.config.timeout) as client:
        response = await client.post(
          f"{self.config.base_url.rstrip('/')}/chat/completions",
          headers=self._headers(),
          json=payload,
        )
        response.raise_for_status()
        return self._parse_response(response.json())

    return await retry_async(_request, max_attempts=self.config.max_retries)

  def stream(
    self,
    messages: list[Message],
    *,
    tools: list[ToolDefinition] | None = None,
    **kwargs: Any,
  ) -> Iterator[str]:
    """Stream text deltas from a chat completion."""
    payload = self._build_payload(messages, tools=tools, stream=True, **kwargs)

    with httpx.Client(timeout=self.config.timeout) as client, client.stream(
      "POST",
      f"{self.config.base_url.rstrip('/')}/chat/completions",
      headers=self._headers(),
      json=payload,
    ) as response:
      response.raise_for_status()
      for line in response.iter_lines():
        if not line or not line.startswith("data: "):
          continue
        chunk = line[6:]
        if chunk == "[DONE]":
          break
        data = json.loads(chunk)
        delta = data.get("choices", [{}])[0].get("delta", {})
        content = delta.get("content")
        if content:
          yield content

  async def astream(
    self,
    messages: list[Message],
    *,
    tools: list[ToolDefinition] | None = None,
    **kwargs: Any,
  ) -> AsyncIterator[str]:
    """Stream text deltas asynchronously."""
    payload = self._build_payload(messages, tools=tools, stream=True, **kwargs)

    async with httpx.AsyncClient(timeout=self.config.timeout) as client, client.stream(
      "POST",
      f"{self.config.base_url.rstrip('/')}/chat/completions",
      headers=self._headers(),
      json=payload,
    ) as response:
      response.raise_for_status()
      async for line in response.aiter_lines():
        if not line or not line.startswith("data: "):
          continue
        chunk = line[6:]
        if chunk == "[DONE]":
          break
        data = json.loads(chunk)
        delta = data.get("choices", [{}])[0].get("delta", {})
        content = delta.get("content")
        if content:
          yield content

  def chat(self, prompt: str, *, system: str | None = None, **kwargs: Any) -> str:
    """Convenience helper for a single-turn chat."""
    messages: list[Message] = []
    if system:
      messages.append(Message(role=Role.SYSTEM, content=system))
    messages.append(Message(role=Role.USER, content=prompt))
    result = self.complete(messages, **kwargs)
    return result.content or ""

  async def achat(self, prompt: str, *, system: str | None = None, **kwargs: Any) -> str:
    """Async convenience helper for a single-turn chat."""
    messages: list[Message] = []
    if system:
      messages.append(Message(role=Role.SYSTEM, content=system))
    messages.append(Message(role=Role.USER, content=prompt))
    result = await self.acomplete(messages, **kwargs)
    return result.content or ""
