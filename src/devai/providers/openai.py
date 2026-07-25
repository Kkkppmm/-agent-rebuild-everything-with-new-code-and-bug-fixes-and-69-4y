"""OpenAI-compatible provider (OpenAI, Azure, local gateways)."""

from __future__ import annotations

import json
from typing import AsyncIterator

import httpx

from devai.exceptions import APIError, ConfigurationError
from devai.providers.base import BaseProvider
from devai.types import (
  ChatResponse,
  EmbeddingResponse,
  Message,
  ProviderConfig,
  StreamChunk,
  ToolCall,
  ToolDefinition,
)


class OpenAIProvider(BaseProvider):
  """Provider for OpenAI and OpenAI-compatible APIs."""

  DEFAULT_BASE_URL = "https://api.openai.com/v1"
  DEFAULT_MODEL = "gpt-4o-mini"
  DEFAULT_EMBED_MODEL = "text-embedding-3-small"

  def __init__(self, config: ProviderConfig):
    super().__init__(config)
    self.base_url = (config.base_url or self.DEFAULT_BASE_URL).rstrip("/")
    self.api_key = config.api_key
    if not self.api_key:
      raise ConfigurationError(
        "OpenAI provider requires an API key. Set api_key in ProviderConfig or DEVAI_API_KEY env."
      )

  def _headers(self) -> dict[str, str]:
    return {
      "Authorization": f"Bearer {self.api_key}",
      "Content-Type": "application/json",
    }

  def _build_payload(
    self,
    messages: list[Message],
    model: str,
    tools: list[ToolDefinition] | None,
    temperature: float | None,
    max_tokens: int | None,
    stream: bool = False,
  ) -> dict:
    payload: dict = {
      "model": model,
      "messages": [m.to_dict() for m in messages],
      "stream": stream,
    }
    if tools:
      payload["tools"] = [t.to_schema() for t in tools]
    if temperature is not None:
      payload["temperature"] = temperature
    if max_tokens is not None:
      payload["max_tokens"] = max_tokens
    return payload

  def _parse_tool_calls(self, raw_calls: list[dict] | None) -> list[ToolCall] | None:
    if not raw_calls:
      return None
    result = []
    for call in raw_calls:
      func = call.get("function", {})
      args_raw = func.get("arguments", "{}")
      try:
        args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
      except json.JSONDecodeError:
        args = {"raw": args_raw}
      result.append(
        ToolCall(
          id=call.get("id", ""),
          name=func.get("name", ""),
          arguments=args,
        )
      )
    return result

  def _parse_chat_response(self, data: dict, model: str) -> ChatResponse:
    choice = data.get("choices", [{}])[0]
    message = choice.get("message", {})
    return ChatResponse(
      content=message.get("content") or "",
      role=message.get("role", "assistant"),
      tool_calls=self._parse_tool_calls(message.get("tool_calls")),
      model=data.get("model", model),
      usage=data.get("usage"),
      raw=data,
    )

  async def chat(
    self,
    messages: list[Message],
    model: str | None = None,
    tools: list[ToolDefinition] | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
  ) -> ChatResponse:
    model = model or self.config.model or self.DEFAULT_MODEL
    payload = self._build_payload(messages, model, tools, temperature, max_tokens)

    async with httpx.AsyncClient(timeout=self.config.timeout) as client:
      response = await client.post(
        f"{self.base_url}/chat/completions",
        headers=self._headers(),
        json=payload,
      )
      if response.status_code >= 400:
        raise APIError(
          f"OpenAI API error: {response.status_code}",
          status_code=response.status_code,
          body=response.text,
        )
      return self._parse_chat_response(response.json(), model)

  async def stream(
    self,
    messages: list[Message],
    model: str | None = None,
    tools: list[ToolDefinition] | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
  ) -> AsyncIterator[StreamChunk]:
    model = model or self.config.model or self.DEFAULT_MODEL
    payload = self._build_payload(messages, model, tools, temperature, max_tokens, stream=True)

    async with httpx.AsyncClient(timeout=self.config.timeout) as client:
      async with client.stream(
        "POST",
        f"{self.base_url}/chat/completions",
        headers=self._headers(),
        json=payload,
      ) as response:
        if response.status_code >= 400:
          body = await response.aread()
          raise APIError(
            f"OpenAI API error: {response.status_code}",
            status_code=response.status_code,
            body=body.decode(),
          )
        async for line in response.aiter_lines():
          if not line.startswith("data: "):
            continue
          data_str = line[6:]
          if data_str.strip() == "[DONE]":
            yield StreamChunk(done=True)
            break
          try:
            data = json.loads(data_str)
          except json.JSONDecodeError:
            continue
          choice = data.get("choices", [{}])[0]
          delta = choice.get("delta", {})
          content = delta.get("content") or ""
          tool_calls = self._parse_tool_calls(delta.get("tool_calls"))
          yield StreamChunk(content=content, tool_calls=tool_calls)

  async def embed(
    self,
    texts: list[str],
    model: str | None = None,
  ) -> EmbeddingResponse:
    model = model or self.config.extra.get("embed_model") or self.DEFAULT_EMBED_MODEL
    payload = {"model": model, "input": texts}

    async with httpx.AsyncClient(timeout=self.config.timeout) as client:
      response = await client.post(
        f"{self.base_url}/embeddings",
        headers=self._headers(),
        json=payload,
      )
      if response.status_code >= 400:
        raise APIError(
          f"OpenAI API error: {response.status_code}",
          status_code=response.status_code,
          body=response.text,
        )
      data = response.json()
      embeddings = [item["embedding"] for item in data.get("data", [])]
      return EmbeddingResponse(
        embeddings=embeddings,
        model=data.get("model", model),
        usage=data.get("usage"),
      )
