"""Anthropic Claude provider."""

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
  Role,
  StreamChunk,
  ToolCall,
  ToolDefinition,
)


class AnthropicProvider(BaseProvider):
  """Provider for Anthropic's Claude API."""

  DEFAULT_BASE_URL = "https://api.anthropic.com"
  DEFAULT_MODEL = "claude-3-5-sonnet-20241022"
  API_VERSION = "2023-06-01"

  def __init__(self, config: ProviderConfig):
    super().__init__(config)
    self.base_url = (config.base_url or self.DEFAULT_BASE_URL).rstrip("/")
    self.api_key = config.api_key
    if not self.api_key:
      raise ConfigurationError(
        "Anthropic provider requires an API key. Set api_key in ProviderConfig or DEVAI_API_KEY env."
      )

  def _headers(self) -> dict[str, str]:
    return {
      "x-api-key": self.api_key,
      "anthropic-version": self.API_VERSION,
      "Content-Type": "application/json",
    }

  def _convert_messages(self, messages: list[Message]) -> tuple[str | None, list[dict]]:
    system_prompt: str | None = None
    converted: list[dict] = []

    for msg in messages:
      role = str(msg.role)
      if role == Role.SYSTEM or role == "system":
        system_prompt = msg.content
        continue
      if role == Role.TOOL or role == "tool":
        converted.append(
          {
            "role": "user",
            "content": [
              {
                "type": "tool_result",
                "tool_use_id": msg.tool_call_id or "",
                "content": msg.content,
              }
            ],
          }
        )
      elif msg.tool_calls:
        content_blocks: list[dict] = []
        if msg.content:
          content_blocks.append({"type": "text", "text": msg.content})
        for tc in msg.tool_calls:
          content_blocks.append(
            {
              "type": "tool_use",
              "id": tc.id,
              "name": tc.name,
              "input": tc.arguments,
            }
          )
        converted.append({"role": "assistant", "content": content_blocks})
      else:
        anthropic_role = "assistant" if role in ("assistant", Role.ASSISTANT) else "user"
        converted.append({"role": anthropic_role, "content": msg.content})

    return system_prompt, converted

  def _convert_tools(self, tools: list[ToolDefinition] | None) -> list[dict] | None:
    if not tools:
      return None
    return [
      {
        "name": t.name,
        "description": t.description,
        "input_schema": t.parameters,
      }
      for t in tools
    ]

  async def chat(
    self,
    messages: list[Message],
    model: str | None = None,
    tools: list[ToolDefinition] | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
  ) -> ChatResponse:
    model = model or self.config.model or self.DEFAULT_MODEL
    system_prompt, converted = self._convert_messages(messages)
    payload: dict = {
      "model": model,
      "messages": converted,
      "max_tokens": max_tokens or 4096,
    }
    if system_prompt:
      payload["system"] = system_prompt
    if temperature is not None:
      payload["temperature"] = temperature
    converted_tools = self._convert_tools(tools)
    if converted_tools:
      payload["tools"] = converted_tools

    async with httpx.AsyncClient(timeout=self.config.timeout) as client:
      response = await client.post(
        f"{self.base_url}/v1/messages",
        headers=self._headers(),
        json=payload,
      )
      if response.status_code >= 400:
        raise APIError(
          f"Anthropic API error: {response.status_code}",
          status_code=response.status_code,
          body=response.text,
        )
      data = response.json()
      return self._parse_response(data, model)

  def _parse_response(self, data: dict, model: str) -> ChatResponse:
    content_blocks = data.get("content", [])
    text_parts: list[str] = []
    tool_calls: list[ToolCall] = []

    for block in content_blocks:
      if block.get("type") == "text":
        text_parts.append(block.get("text", ""))
      elif block.get("type") == "tool_use":
        tool_calls.append(
          ToolCall(
            id=block.get("id", ""),
            name=block.get("name", ""),
            arguments=block.get("input", {}),
          )
        )

    return ChatResponse(
      content="\n".join(text_parts),
      role="assistant",
      tool_calls=tool_calls or None,
      model=data.get("model", model),
      usage=data.get("usage"),
      raw=data,
    )

  async def stream(
    self,
    messages: list[Message],
    model: str | None = None,
    tools: list[ToolDefinition] | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
  ) -> AsyncIterator[StreamChunk]:
    model = model or self.config.model or self.DEFAULT_MODEL
    system_prompt, converted = self._convert_messages(messages)
    payload: dict = {
      "model": model,
      "messages": converted,
      "max_tokens": max_tokens or 4096,
      "stream": True,
    }
    if system_prompt:
      payload["system"] = system_prompt
    if temperature is not None:
      payload["temperature"] = temperature
    converted_tools = self._convert_tools(tools)
    if converted_tools:
      payload["tools"] = converted_tools

    async with httpx.AsyncClient(timeout=self.config.timeout) as client:
      async with client.stream(
        "POST",
        f"{self.base_url}/v1/messages",
        headers=self._headers(),
        json=payload,
      ) as response:
        if response.status_code >= 400:
          body = await response.aread()
          raise APIError(
            f"Anthropic API error: {response.status_code}",
            status_code=response.status_code,
            body=body.decode(),
          )
        async for line in response.aiter_lines():
          if not line.startswith("data: "):
            continue
          try:
            data = json.loads(line[6:])
          except json.JSONDecodeError:
            continue
          event_type = data.get("type")
          if event_type == "content_block_delta":
            delta = data.get("delta", {})
            if delta.get("type") == "text_delta":
              yield StreamChunk(content=delta.get("text", ""))
          elif event_type == "message_stop":
            yield StreamChunk(done=True)

  async def embed(
    self,
    texts: list[str],
    model: str | None = None,
  ) -> EmbeddingResponse:
    raise NotImplementedError(
      "Anthropic does not provide embeddings. Use OpenAI or Ollama provider for embeddings."
    )
