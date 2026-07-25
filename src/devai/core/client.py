"""OpenAI-compatible LLM client."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import ConfigurationError, LLMError, RateLimitError
from devai.core.models import ChatResponse, Message, ToolCall, ToolDefinition


class LLMClient:
  """HTTP client for OpenAI-compatible chat completion APIs."""

  def __init__(self, config: DevAIConfig | None = None) -> None:
    self.config = config or DevAIConfig.from_env()
    self._client: httpx.Client | None = None
    self._async_client: httpx.AsyncClient | None = None

  def _headers(self) -> dict[str, str]:
    if not self.config.api_key:
      raise ConfigurationError(
        "API key is required. Set DEVAI_API_KEY or OPENAI_API_KEY."
      )
    headers = {
      "Authorization": f"Bearer {self.config.api_key}",
      "Content-Type": "application/json",
    }
    headers.update(self.config.extra_headers)
    return headers

  def _get_client(self) -> httpx.Client:
    if self._client is None:
      self._client = httpx.Client(
        base_url=self.config.base_url.rstrip("/"),
        headers=self._headers(),
        timeout=self.config.timeout,
      )
    return self._client

  def _get_async_client(self) -> httpx.AsyncClient:
    if self._async_client is None:
      self._async_client = httpx.AsyncClient(
        base_url=self.config.base_url.rstrip("/"),
        headers=self._headers(),
        timeout=self.config.timeout,
      )
    return self._async_client

  def _build_payload(
    self,
    messages: list[Message],
    tools: list[ToolDefinition] | None = None,
    stream: bool = False,
    *,
    json_mode: bool = False,
    **kwargs: Any,
  ) -> dict[str, Any]:
    payload: dict[str, Any] = {
      "model": kwargs.get("model", self.config.model),
      "messages": [m.to_api_dict() for m in messages],
      "temperature": kwargs.get("temperature", self.config.temperature),
      "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
      "stream": stream,
    }
    if tools:
      payload["tools"] = [t.to_api_dict() for t in tools]
    if json_mode:
      payload["response_format"] = {"type": "json_object"}
    return payload

  def _parse_response(self, data: dict[str, Any]) -> ChatResponse:
    choice = data["choices"][0]
    message = choice["message"]
    tool_calls: list[ToolCall] = []
    for tc in message.get("tool_calls") or []:
      func = tc["function"]
      args = func.get("arguments", "{}")
      if isinstance(args, str):
        args = json.loads(args) if args else {}
      tool_calls.append(
        ToolCall(id=tc["id"], name=func["name"], arguments=args)
      )
    return ChatResponse(
      content=message.get("content") or "",
      tool_calls=tool_calls,
      model=data.get("model", ""),
      finish_reason=choice.get("finish_reason", ""),
      usage=data.get("usage", {}),
    )

  def _handle_error(self, response: httpx.Response) -> None:
    if response.status_code == 429:
      raise RateLimitError(f"Rate limited: {response.text}")
    if response.status_code >= 400:
      raise LLMError(f"API error {response.status_code}: {response.text}")

  def _is_retryable(self, exc: Exception) -> bool:
    if isinstance(exc, RateLimitError):
      return True
    if isinstance(exc, LLMError):
      return any(code in str(exc) for code in ("500", "502", "503", "504"))
    return False

  def _backoff_delay(self, attempt: int) -> float:
    return min(2 ** attempt, 30)

  def _request_with_retry(
    self,
    messages: list[Message],
    tools: list[ToolDefinition] | None = None,
    **kwargs: Any,
  ) -> ChatResponse:
    json_mode = kwargs.pop("json_mode", False)
    payload = self._build_payload(messages, tools, stream=False, json_mode=json_mode, **kwargs)
    last_error: Exception | None = None

    for attempt in range(self.config.max_retries + 1):
      try:
        response = self._get_client().post("/chat/completions", json=payload)
        self._handle_error(response)
        return self._parse_response(response.json())
      except Exception as exc:
        last_error = exc
        if attempt >= self.config.max_retries or not self._is_retryable(exc):
          raise
        time.sleep(self._backoff_delay(attempt))

    raise last_error  # pragma: no cover

  async def _arequest_with_retry(
    self,
    messages: list[Message],
    tools: list[ToolDefinition] | None = None,
    **kwargs: Any,
  ) -> ChatResponse:
    json_mode = kwargs.pop("json_mode", False)
    payload = self._build_payload(messages, tools, stream=False, json_mode=json_mode, **kwargs)
    last_error: Exception | None = None

    for attempt in range(self.config.max_retries + 1):
      try:
        response = await self._get_async_client().post("/chat/completions", json=payload)
        self._handle_error(response)
        return self._parse_response(response.json())
      except Exception as exc:
        last_error = exc
        if attempt >= self.config.max_retries or not self._is_retryable(exc):
          raise
        await asyncio.sleep(self._backoff_delay(attempt))

    raise last_error  # pragma: no cover

  def chat(
    self,
    messages: list[Message],
    tools: list[ToolDefinition] | None = None,
    **kwargs: Any,
  ) -> ChatResponse:
    """Send a chat completion request."""
    return self._request_with_retry(messages, tools, **kwargs)

  async def achat(
    self,
    messages: list[Message],
    tools: list[ToolDefinition] | None = None,
    **kwargs: Any,
  ) -> ChatResponse:
    """Async chat completion request."""
    return await self._arequest_with_retry(messages, tools, **kwargs)

  def chat_json(
    self,
    messages: list[Message],
    **kwargs: Any,
  ) -> dict[str, Any]:
    """Request a JSON object response and parse it."""
    response = self._request_with_retry(messages, json_mode=True, **kwargs)
    try:
      return json.loads(response.content)
    except json.JSONDecodeError as exc:
      raise LLMError(f"Failed to parse JSON response: {exc}") from exc

  async def achat_json(
    self,
    messages: list[Message],
    **kwargs: Any,
  ) -> dict[str, Any]:
    """Async version of chat_json."""
    response = await self._arequest_with_retry(messages, json_mode=True, **kwargs)
    try:
      return json.loads(response.content)
    except json.JSONDecodeError as exc:
      raise LLMError(f"Failed to parse JSON response: {exc}") from exc

  def stream(
    self,
    messages: list[Message],
    tools: list[ToolDefinition] | None = None,
    **kwargs: Any,
  ) -> Iterator[str]:
    """Stream chat completion content tokens."""
    payload = self._build_payload(messages, tools, stream=True, **kwargs)
    with self._get_client().stream("POST", "/chat/completions", json=payload) as resp:
      self._handle_error(resp)
      for line in resp.iter_lines():
        if not line.startswith("data: "):
          continue
        data_str = line[6:]
        if data_str.strip() == "[DONE]":
          break
        chunk = json.loads(data_str)
        delta = chunk["choices"][0].get("delta", {})
        content = delta.get("content")
        if content:
          yield content

  async def astream(
    self,
    messages: list[Message],
    tools: list[ToolDefinition] | None = None,
    **kwargs: Any,
  ) -> AsyncIterator[str]:
    """Async stream of chat completion content tokens."""
    payload = self._build_payload(messages, tools, stream=True, **kwargs)
    async with self._get_async_client().stream(
      "POST", "/chat/completions", json=payload
    ) as resp:
      self._handle_error(resp)
      async for line in resp.aiter_lines():
        if not line.startswith("data: "):
          continue
        data_str = line[6:]
        if data_str.strip() == "[DONE]":
          break
        chunk = json.loads(data_str)
        delta = chunk["choices"][0].get("delta", {})
        content = delta.get("content")
        if content:
          yield content

  def close(self) -> None:
    if self._client:
      self._client.close()
      self._client = None

  async def aclose(self) -> None:
    if self._async_client:
      await self._async_client.aclose()
      self._async_client = None

  def __enter__(self) -> LLMClient:
    return self

  def __exit__(self, *args: Any) -> None:
    self.close()
