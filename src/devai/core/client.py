"""LLM client implementations."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from typing import Any, Self

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import AuthenticationError, ProviderError, RateLimitError
from devai.core.models import CompletionResult, Message, Role, ToolCall, ToolDefinition
from devai.core.retries import with_retries


class LLMClient:
  """Provider-agnostic LLM client supporting OpenAI and Anthropic APIs."""

  def __init__(self, config: DevAIConfig | None = None) -> None:
    self.config = config or DevAIConfig.from_env()
    self.config.validate_provider()
    self._http = httpx.Client(timeout=self.config.timeout)

  def complete(
    self,
    messages: list[Message],
    *,
    tools: list[ToolDefinition] | None = None,
    json_mode: bool = False,
    temperature: float | None = None,
    max_tokens: int | None = None,
  ) -> CompletionResult:
    return with_retries(
      lambda: self._complete_once(
        messages,
        tools=tools,
        json_mode=json_mode,
        temperature=temperature,
        max_tokens=max_tokens,
      ),
      max_retries=self.config.max_retries,
    )

  def stream(
    self,
    messages: list[Message],
    *,
    temperature: float | None = None,
    max_tokens: int | None = None,
  ) -> Iterator[str]:
    if self.config.provider == "openai":
      yield from self._stream_openai(messages, temperature=temperature, max_tokens=max_tokens)
    elif self.config.provider == "anthropic":
      yield from self._stream_anthropic(messages, temperature=temperature, max_tokens=max_tokens)
    else:
      result = self.complete(messages, temperature=temperature, max_tokens=max_tokens)
      yield result.content

  async def acomplete(
    self,
    messages: list[Message],
    *,
    tools: list[ToolDefinition] | None = None,
    json_mode: bool = False,
    temperature: float | None = None,
    max_tokens: int | None = None,
  ) -> CompletionResult:
    import asyncio

    return await asyncio.to_thread(
      self.complete,
      messages,
      tools=tools,
      json_mode=json_mode,
      temperature=temperature,
      max_tokens=max_tokens,
    )

  async def astream(
    self,
    messages: list[Message],
    *,
    temperature: float | None = None,
    max_tokens: int | None = None,
  ) -> AsyncIterator[str]:
    import asyncio

    queue: asyncio.Queue[str | None] = asyncio.Queue()

    def _produce() -> None:
      try:
        for chunk in self.stream(messages, temperature=temperature, max_tokens=max_tokens):
          queue.put_nowait(chunk)
      finally:
        queue.put_nowait(None)

    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, _produce)
    while True:
      chunk = await queue.get()
      if chunk is None:
        break
      yield chunk

  def _complete_once(
    self,
    messages: list[Message],
    *,
    tools: list[ToolDefinition] | None = None,
    json_mode: bool = False,
    temperature: float | None = None,
    max_tokens: int | None = None,
  ) -> CompletionResult:
    if self.config.provider == "openai":
      return self._complete_openai(
        messages,
        tools=tools,
        json_mode=json_mode,
        temperature=temperature,
        max_tokens=max_tokens,
      )
    if self.config.provider == "anthropic":
      return self._complete_anthropic(
        messages,
        tools=tools,
        temperature=temperature,
        max_tokens=max_tokens,
      )
    raise ProviderError(f"Unsupported provider: {self.config.provider}")

  def _complete_openai(
    self,
    messages: list[Message],
    *,
    tools: list[ToolDefinition] | None = None,
    json_mode: bool = False,
    temperature: float | None = None,
    max_tokens: int | None = None,
  ) -> CompletionResult:
    payload: dict[str, Any] = {
      "model": self.config.model,
      "messages": [m.to_dict() for m in messages],
      "temperature": temperature if temperature is not None else self.config.temperature,
      "max_tokens": max_tokens or self.config.max_tokens,
    }
    if tools:
      payload["tools"] = [t.to_openai_schema() for t in tools]
    if json_mode:
      payload["response_format"] = {"type": "json_object"}

    response = self._http.post(
      f"{self.config.effective_base_url}/chat/completions",
      headers=self._auth_headers(),
      json=payload,
    )
    return self._parse_openai_response(response)

  def _complete_anthropic(
    self,
    messages: list[Message],
    *,
    tools: list[ToolDefinition] | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
  ) -> CompletionResult:
    system_msgs = [m.content for m in messages if m.role == Role.SYSTEM]
    chat_msgs = [
      {"role": "user" if m.role == Role.USER else "assistant", "content": m.content}
      for m in messages
      if m.role in (Role.USER, Role.ASSISTANT)
    ]
    payload: dict[str, Any] = {
      "model": self.config.model,
      "messages": chat_msgs,
      "max_tokens": max_tokens or self.config.max_tokens,
      "temperature": temperature if temperature is not None else self.config.temperature,
    }
    if system_msgs:
      payload["system"] = "\n".join(system_msgs)
    if tools:
      payload["tools"] = [
        {
          "name": t.name,
          "description": t.description,
          "input_schema": t.parameters,
        }
        for t in tools
      ]

    response = self._http.post(
      f"{self.config.effective_base_url}/messages",
      headers=self._anthropic_headers(),
      json=payload,
    )
    return self._parse_anthropic_response(response)

  def _stream_openai(
    self,
    messages: list[Message],
    *,
    temperature: float | None = None,
    max_tokens: int | None = None,
  ) -> Iterator[str]:
    payload = {
      "model": self.config.model,
      "messages": [m.to_dict() for m in messages],
      "temperature": temperature if temperature is not None else self.config.temperature,
      "max_tokens": max_tokens or self.config.max_tokens,
      "stream": True,
    }
    with self._http.stream(
      "POST",
      f"{self.config.effective_base_url}/chat/completions",
      headers=self._auth_headers(),
      json=payload,
    ) as response:
      self._check_response(response)
      for line in response.iter_lines():
        if not line.startswith("data: "):
          continue
        data = line[6:]
        if data == "[DONE]":
          break
        chunk = json.loads(data)
        delta = chunk.get("choices", [{}])[0].get("delta", {})
        if content := delta.get("content"):
          yield content

  def _stream_anthropic(
    self,
    messages: list[Message],
    *,
    temperature: float | None = None,
    max_tokens: int | None = None,
  ) -> Iterator[str]:
    system_msgs = [m.content for m in messages if m.role == Role.SYSTEM]
    chat_msgs = [
      {"role": "user" if m.role == Role.USER else "assistant", "content": m.content}
      for m in messages
      if m.role in (Role.USER, Role.ASSISTANT)
    ]
    payload: dict[str, Any] = {
      "model": self.config.model,
      "messages": chat_msgs,
      "max_tokens": max_tokens or self.config.max_tokens,
      "temperature": temperature if temperature is not None else self.config.temperature,
      "stream": True,
    }
    if system_msgs:
      payload["system"] = "\n".join(system_msgs)

    with self._http.stream(
      "POST",
      f"{self.config.effective_base_url}/messages",
      headers=self._anthropic_headers(),
      json=payload,
    ) as response:
      self._check_response(response)
      for line in response.iter_lines():
        if not line.startswith("data: "):
          continue
        event = json.loads(line[6:])
        if event.get("type") == "content_block_delta" and (
          text := event.get("delta", {}).get("text")
        ):
          yield text

  def _auth_headers(self) -> dict[str, str]:
    return {
      "Authorization": f"Bearer {self.config.api_key}",
      "Content-Type": "application/json",
    }

  def _anthropic_headers(self) -> dict[str, str]:
    return {
      "x-api-key": self.config.api_key or "",
      "anthropic-version": "2023-06-01",
      "Content-Type": "application/json",
    }

  def _check_response(self, response: httpx.Response) -> None:
    if response.status_code == 401:
      raise AuthenticationError("Invalid API key")
    if response.status_code == 429:
      raise RateLimitError("Rate limit exceeded")
    if response.status_code >= 400:
      raise ProviderError(f"API error {response.status_code}: {response.text}")

  def _parse_openai_response(self, response: httpx.Response) -> CompletionResult:
    self._check_response(response)
    data = response.json()
    choice = data["choices"][0]
    message = choice["message"]
    tool_calls = None
    if raw_tools := message.get("tool_calls"):
      tool_calls = [
        ToolCall(
          id=tc["id"],
          name=tc["function"]["name"],
          arguments=json.loads(tc["function"]["arguments"]),
        )
        for tc in raw_tools
      ]
    return CompletionResult(
      content=message.get("content") or "",
      model=data.get("model", self.config.model),
      finish_reason=choice.get("finish_reason"),
      tool_calls=tool_calls,
      usage=data.get("usage", {}),
    )

  def _parse_anthropic_response(self, response: httpx.Response) -> CompletionResult:
    self._check_response(response)
    data = response.json()
    content_parts = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
    tool_calls = [
      ToolCall(id=b.get("id", ""), name=b["name"], arguments=b.get("input", {}))
      for b in data.get("content", [])
      if b.get("type") == "tool_use"
    ]
    return CompletionResult(
      content="".join(content_parts),
      model=data.get("model", self.config.model),
      finish_reason=data.get("stop_reason"),
      tool_calls=tool_calls or None,
      usage={
        "input_tokens": data.get("usage", {}).get("input_tokens", 0),
        "output_tokens": data.get("usage", {}).get("output_tokens", 0),
      },
    )

  def close(self) -> None:
    self._http.close()

  def __enter__(self) -> Self:
    return self

  def __exit__(self, *args: object) -> None:
    self.close()


class MockLLMClient:
  """Deterministic mock client for testing without API keys."""

  def __init__(self, responses: dict[str, str] | None = None) -> None:
    self.responses = responses or {}
    self.call_history: list[list[Message]] = []

  def complete(
    self,
    messages: list[Message],
    *,
    tools: list[ToolDefinition] | None = None,
    json_mode: bool = False,
    temperature: float | None = None,
    max_tokens: int | None = None,
  ) -> CompletionResult:
    self.call_history.append(messages)
    last = messages[-1].content if messages else ""
    for key, response in self.responses.items():
      if key.lower() in last.lower():
        return CompletionResult(content=response, model="mock")
    return CompletionResult(
      content=f"[Mock response to: {last[:80]}...]",
      model="mock",
      usage={"prompt_tokens": 10, "completion_tokens": 20},
    )

  def stream(
    self,
    messages: list[Message],
    *,
    temperature: float | None = None,
    max_tokens: int | None = None,
  ) -> Iterator[str]:
    result = self.complete(messages, temperature=temperature, max_tokens=max_tokens)
    words = result.content.split(" ")
    for i, word in enumerate(words):
      yield word + (" " if i < len(words) - 1 else "")

  async def acomplete(self, messages: list[Message], **kwargs: object) -> CompletionResult:
    return self.complete(messages, **kwargs)  # type: ignore[arg-type]

  async def astream(self, messages: list[Message], **kwargs: object) -> AsyncIterator[str]:
    for chunk in self.stream(messages, **kwargs):  # type: ignore[arg-type]
      yield chunk


class EmbeddingClient:
  """Simple embedding client using OpenAI's embedding API."""

  def __init__(self, config: DevAIConfig | None = None) -> None:
    self.config = config or DevAIConfig.from_env()
    self.config.validate_provider()
    self._http = httpx.Client(timeout=self.config.timeout)
    self.model = "text-embedding-3-small"

  def embed(self, texts: list[str]) -> list[list[float]]:
    if self.config.provider == "mock":
      return [[float(i % 10) / 10.0 for i in range(8)] for _ in texts]
    response = self._http.post(
      f"{self.config.effective_base_url}/embeddings",
      headers={"Authorization": f"Bearer {self.config.api_key}"},
      json={"model": self.model, "input": texts},
    )
    if response.status_code >= 400:
      raise ProviderError(f"Embedding error: {response.text}")
    data = response.json()
    return [item["embedding"] for item in data["data"]]

  def embed_one(self, text: str) -> list[float]:
    return self.embed([text])[0]
