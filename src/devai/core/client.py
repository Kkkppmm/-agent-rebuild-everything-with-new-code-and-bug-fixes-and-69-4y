"""LLM client implementations."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Callable, Iterator
from typing import Any

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import LLMError, RateLimitError
from devai.core.models import CompletionResult, Message, ToolCall, ToolDefinition


def _messages_to_api(messages: list[Message]) -> list[dict[str, Any]]:
  return [m.to_dict() for m in messages]


class LLMClient:
  """OpenAI-compatible LLM client with sync/async and streaming support."""

  def __init__(self, config: DevAIConfig | None = None) -> None:
    self.config = config or DevAIConfig()

  def complete(
    self,
    messages: list[Message],
    *,
    tools: list[ToolDefinition] | None = None,
    json_mode: bool = False,
    temperature: float | None = None,
    max_tokens: int | None = None,
    model: str | None = None,
  ) -> CompletionResult:
    payload = self._build_payload(
      messages, tools=tools, json_mode=json_mode,
      temperature=temperature, max_tokens=max_tokens, model=model,
    )
    data = self._request("POST", "/chat/completions", payload)
    return self._parse_completion(data)

  async def acomplete(
    self,
    messages: list[Message],
    *,
    tools: list[ToolDefinition] | None = None,
    json_mode: bool = False,
    temperature: float | None = None,
    max_tokens: int | None = None,
    model: str | None = None,
  ) -> CompletionResult:
    payload = self._build_payload(
      messages, tools=tools, json_mode=json_mode,
      temperature=temperature, max_tokens=max_tokens, model=model,
    )
    data = await self._arequest("POST", "/chat/completions", payload)
    return self._parse_completion(data)

  def stream(
    self,
    messages: list[Message],
    *,
    temperature: float | None = None,
    max_tokens: int | None = None,
    model: str | None = None,
  ) -> Iterator[str]:
    payload = self._build_payload(
      messages, temperature=temperature, max_tokens=max_tokens, model=model,
    )
    payload["stream"] = True
    with httpx.Client(timeout=self.config.timeout) as client:
      for attempt in range(self.config.max_retries + 1):
        try:
          with client.stream(
            "POST",
            f"{self.config.base_url.rstrip('/')}/chat/completions",
            headers=self._headers(),
            json=payload,
          ) as response:
            self._check_response(response)
            for line in response.iter_lines():
              chunk = self._parse_stream_line(line)
              if chunk:
                yield chunk
          return
        except RateLimitError:
          if attempt >= self.config.max_retries:
            raise
          time.sleep(self.config.retry_delay * (2 ** attempt))

  async def astream(
    self,
    messages: list[Message],
    *,
    temperature: float | None = None,
    max_tokens: int | None = None,
    model: str | None = None,
  ) -> AsyncIterator[str]:
    payload = self._build_payload(
      messages, temperature=temperature, max_tokens=max_tokens, model=model,
    )
    payload["stream"] = True
    async with httpx.AsyncClient(timeout=self.config.timeout) as client:
      for attempt in range(self.config.max_retries + 1):
        try:
          async with client.stream(
            "POST",
            f"{self.config.base_url.rstrip('/')}/chat/completions",
            headers=self._headers(),
            json=payload,
          ) as response:
            self._check_response(response)
            async for line in response.aiter_lines():
              chunk = self._parse_stream_line(line)
              if chunk:
                yield chunk
          return
        except RateLimitError:
          if attempt >= self.config.max_retries:
            raise
          await asyncio.sleep(self.config.retry_delay * (2 ** attempt))

  def _build_payload(
    self,
    messages: list[Message],
    *,
    tools: list[ToolDefinition] | None = None,
    json_mode: bool = False,
    temperature: float | None = None,
    max_tokens: int | None = None,
    model: str | None = None,
  ) -> dict[str, Any]:
    payload: dict[str, Any] = {
      "model": model or self.config.model,
      "messages": _messages_to_api(messages),
      "temperature": temperature if temperature is not None else self.config.temperature,
      "max_tokens": max_tokens or self.config.max_tokens,
    }
    if tools:
      payload["tools"] = [t.to_openai_tool() for t in tools]
    if json_mode:
      payload["response_format"] = {"type": "json_object"}
    payload.update(self.config.extra_body)
    return payload

  def _headers(self) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if self.config.api_key:
      headers["Authorization"] = f"Bearer {self.config.api_key}"
    headers.update(self.config.extra_headers)
    return headers

  def _request(self, method: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    url = f"{self.config.base_url.rstrip('/')}{path}"
    for attempt in range(self.config.max_retries + 1):
      try:
        with httpx.Client(timeout=self.config.timeout) as client:
          response = client.request(method, url, headers=self._headers(), json=payload)
          self._check_response(response)
          return response.json()
      except RateLimitError:
        if attempt >= self.config.max_retries:
          raise
        time.sleep(self.config.retry_delay * (2 ** attempt))
    raise LLMError("Request failed after retries")

  async def _arequest(self, method: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    url = f"{self.config.base_url.rstrip('/')}{path}"
    for attempt in range(self.config.max_retries + 1):
      try:
        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
          response = await client.request(method, url, headers=self._headers(), json=payload)
          self._check_response(response)
          return response.json()
      except RateLimitError:
        if attempt >= self.config.max_retries:
          raise
        await asyncio.sleep(self.config.retry_delay * (2 ** attempt))
    raise LLMError("Request failed after retries")

  def _check_response(self, response: httpx.Response) -> None:
    if response.status_code == 429:
      raise RateLimitError(f"Rate limited: {response.text}")
    if response.status_code >= 400:
      raise LLMError(f"HTTP {response.status_code}: {response.text}")

  def _parse_completion(self, data: dict[str, Any]) -> CompletionResult:
    choice = data["choices"][0]
    message = choice.get("message", {})
    tool_calls: list[ToolCall] = []
    for tc in message.get("tool_calls") or []:
      fn = tc.get("function", {})
      args = fn.get("arguments", "{}")
      if isinstance(args, str):
        try:
          args = json.loads(args)
        except json.JSONDecodeError:
          args = {"raw": args}
      tool_calls.append(ToolCall(id=tc["id"], name=fn["name"], arguments=args))
    return CompletionResult(
      content=message.get("content") or "",
      tool_calls=tool_calls,
      finish_reason=choice.get("finish_reason", "stop"),
      usage=data.get("usage", {}),
      raw=data,
    )

  @staticmethod
  def _parse_stream_line(line: str) -> str | None:
    if not line or not line.startswith("data: "):
      return None
    data = line[6:]
    if data.strip() == "[DONE]":
      return None
    try:
      parsed = json.loads(data)
      delta = parsed["choices"][0].get("delta", {})
      return delta.get("content")
    except (json.JSONDecodeError, KeyError, IndexError):
      return None


class MockLLMClient:
  """Deterministic mock LLM for testing without API keys."""

  def __init__(
    self,
    default_response: str = "Mock LLM response for developer task.",
    responses: list[str] | None = None,
    tool_responses: list[list[ToolCall]] | None = None,
    responder: Callable[[list[Message]], CompletionResult | str] | None = None,
  ) -> None:
    self.default_response = default_response
    self.responses = list(responses or [])
    self.tool_responses = list(tool_responses or [])
    self.responder = responder
    self.calls: list[list[Message]] = []

  def complete(
    self,
    messages: list[Message],
    *,
    tools: list[ToolDefinition] | None = None,
    json_mode: bool = False,
    **kwargs: Any,
  ) -> CompletionResult:
    self.calls.append(messages)
    if self.responder:
      result = self.responder(messages)
      return result if isinstance(result, CompletionResult) else CompletionResult(content=result)
    if self.tool_responses:
      tcs = self.tool_responses.pop(0)
      return CompletionResult(content="", tool_calls=tcs, finish_reason="tool_calls")
    content = self.responses.pop(0) if self.responses else self.default_response
    if json_mode and not content.strip().startswith("{"):
      content = json.dumps({"result": content})
    return CompletionResult(content=content)

  async def acomplete(self, messages: list[Message], **kwargs: Any) -> CompletionResult:
    return self.complete(messages, **kwargs)

  def stream(self, messages: list[Message], **kwargs: Any) -> Iterator[str]:
    self.calls.append(messages)
    content = self.responses.pop(0) if self.responses else self.default_response
    for word in content.split():
      yield word + " "

  async def astream(self, messages: list[Message], **kwargs: Any) -> AsyncIterator[str]:
    for chunk in self.stream(messages, **kwargs):
      yield chunk
