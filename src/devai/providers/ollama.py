"""Ollama local model provider."""

from __future__ import annotations

import json
from typing import AsyncIterator

import httpx

from devai.exceptions import APIError
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


class OllamaProvider(BaseProvider):
  """Provider for locally running Ollama models."""

  DEFAULT_BASE_URL = "http://localhost:11434"
  DEFAULT_MODEL = "llama3.2"
  DEFAULT_EMBED_MODEL = "nomic-embed-text"

  def __init__(self, config: ProviderConfig):
    super().__init__(config)
    self.base_url = (config.base_url or self.DEFAULT_BASE_URL).rstrip("/")

  async def chat(
    self,
    messages: list[Message],
    model: str | None = None,
    tools: list[ToolDefinition] | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
  ) -> ChatResponse:
    model = model or self.config.model or self.DEFAULT_MODEL
    payload: dict = {
      "model": model,
      "messages": [m.to_dict() for m in messages],
      "stream": False,
    }
    if tools:
      payload["tools"] = [t.to_schema() for t in tools]
    options: dict = {}
    if temperature is not None:
      options["temperature"] = temperature
    if max_tokens is not None:
      options["num_predict"] = max_tokens
    if options:
      payload["options"] = options

    async with httpx.AsyncClient(timeout=self.config.timeout) as client:
      response = await client.post(
        f"{self.base_url}/api/chat",
        json=payload,
      )
      if response.status_code >= 400:
        raise APIError(
          f"Ollama API error: {response.status_code}",
          status_code=response.status_code,
          body=response.text,
        )
      data = response.json()
      message = data.get("message", {})
      tool_calls = self._parse_tool_calls(message.get("tool_calls"))
      return ChatResponse(
        content=message.get("content") or "",
        role=message.get("role", "assistant"),
        tool_calls=tool_calls,
        model=model,
        raw=data,
      )

  def _parse_tool_calls(self, raw_calls: list[dict] | None) -> list[ToolCall] | None:
    if not raw_calls:
      return None
    result = []
    for call in raw_calls:
      func = call.get("function", {})
      args_raw = func.get("arguments", {})
      if isinstance(args_raw, str):
        try:
          args = json.loads(args_raw)
        except json.JSONDecodeError:
          args = {"raw": args_raw}
      else:
        args = args_raw
      result.append(
        ToolCall(
          id=call.get("id", call.get("name", "")),
          name=func.get("name", call.get("name", "")),
          arguments=args,
        )
      )
    return result

  async def stream(
    self,
    messages: list[Message],
    model: str | None = None,
    tools: list[ToolDefinition] | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
  ) -> AsyncIterator[StreamChunk]:
    model = model or self.config.model or self.DEFAULT_MODEL
    payload: dict = {
      "model": model,
      "messages": [m.to_dict() for m in messages],
      "stream": True,
    }
    if tools:
      payload["tools"] = [t.to_schema() for t in tools]
    options: dict = {}
    if temperature is not None:
      options["temperature"] = temperature
    if max_tokens is not None:
      options["num_predict"] = max_tokens
    if options:
      payload["options"] = options

    async with httpx.AsyncClient(timeout=self.config.timeout) as client:
      async with client.stream(
        "POST",
        f"{self.base_url}/api/chat",
        json=payload,
      ) as response:
        if response.status_code >= 400:
          body = await response.aread()
          raise APIError(
            f"Ollama API error: {response.status_code}",
            status_code=response.status_code,
            body=body.decode(),
          )
        async for line in response.aiter_lines():
          if not line:
            continue
          try:
            data = json.loads(line)
          except json.JSONDecodeError:
            continue
          if data.get("done"):
            yield StreamChunk(done=True)
            break
          message = data.get("message", {})
          yield StreamChunk(content=message.get("content") or "")

  async def embed(
    self,
    texts: list[str],
    model: str | None = None,
  ) -> EmbeddingResponse:
    model = model or self.config.extra.get("embed_model") or self.DEFAULT_EMBED_MODEL
    embeddings: list[list[float]] = []

    async with httpx.AsyncClient(timeout=self.config.timeout) as client:
      for text in texts:
        response = await client.post(
          f"{self.base_url}/api/embeddings",
          json={"model": model, "prompt": text},
        )
        if response.status_code >= 400:
          raise APIError(
            f"Ollama API error: {response.status_code}",
            status_code=response.status_code,
            body=response.text,
          )
        data = response.json()
        embeddings.append(data.get("embedding", []))

    return EmbeddingResponse(embeddings=embeddings, model=model)
