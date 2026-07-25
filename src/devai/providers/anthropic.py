"""Anthropic Claude provider."""

from __future__ import annotations

import json
from typing import AsyncIterator

from devai.config import DevAIConfig
from devai.exceptions import ConfigurationError
from devai.providers.base import build_client, request_json
from devai.types import (
    ChatResponse,
    EmbeddingResponse,
    Message,
    Role,
    StreamChunk,
    ToolCall,
    ToolDefinition,
    Usage,
)


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, config: DevAIConfig):
        self.config = config
        if not config.api_key:
            raise ConfigurationError(
                "Anthropic provider requires ANTHROPIC_API_KEY or DEVAI_API_KEY."
            )
        self._headers = {
            "x-api-key": config.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

    def _split_messages(self, messages: list[Message]) -> tuple[str | None, list[dict]]:
        system = None
        converted = []
        for msg in messages:
            role = str(msg.role)
            if role == Role.SYSTEM or role == "system":
                system = msg.content
                continue
            if role == Role.TOOL or role == "tool":
                converted.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": msg.tool_call_id,
                                "content": msg.content,
                            }
                        ],
                    }
                )
                continue
            if role == Role.ASSISTANT or role == "assistant":
                content = []
                if msg.content:
                    content.append({"type": "text", "text": msg.content})
                for tc in msg.tool_calls or []:
                    content.append(
                        {
                            "type": "tool_use",
                            "id": tc.id,
                            "name": tc.name,
                            "input": tc.arguments,
                        }
                    )
                converted.append({"role": "assistant", "content": content or msg.content})
                continue
            converted.append({"role": "user", "content": msg.content})
        return system, converted

    def _payload(
        self,
        messages: list[Message],
        *,
        model: str,
        temperature: float,
        max_tokens: int | None,
        tools: list[ToolDefinition] | None,
        stream: bool = False,
    ) -> dict:
        system, converted = self._split_messages(messages)
        body: dict = {
            "model": model,
            "messages": converted,
            "max_tokens": max_tokens or 1024,
            "temperature": temperature,
            "stream": stream,
        }
        if system:
            body["system"] = system
        if tools:
            body["tools"] = [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.parameters
                    or {"type": "object", "properties": {}},
                }
                for t in tools
            ]
        return body

    def _parse_chat(self, data: dict, model: str) -> ChatResponse:
        content_parts = []
        tool_calls = []
        for block in data.get("content", []):
            if block.get("type") == "text":
                content_parts.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                tool_calls.append(
                    ToolCall(id=block["id"], name=block["name"], arguments=block.get("input", {}))
                )
        usage_data = data.get("usage", {})
        return ChatResponse(
            content="".join(content_parts),
            model=data.get("model", model),
            provider=self.name,
            usage=Usage(
                prompt_tokens=usage_data.get("input_tokens", 0),
                completion_tokens=usage_data.get("output_tokens", 0),
                total_tokens=usage_data.get("input_tokens", 0)
                + usage_data.get("output_tokens", 0),
            ),
            tool_calls=tool_calls,
            raw=data,
        )

    async def chat(
        self,
        messages: list[Message],
        *,
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        tools: list[ToolDefinition] | None = None,
    ) -> ChatResponse:
        async with build_client(self.config, headers=self._headers) as client:
            data = await request_json(
                client,
                "POST",
                "/messages",
                provider=self.name,
                json_body=self._payload(
                    messages,
                    model=model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    tools=tools,
                ),
            )
        return self._parse_chat(data, model)

    async def stream(
        self,
        messages: list[Message],
        *,
        model: str,
        temperature: float = 0.7,
        max_tokens: int | None = None,
        tools: list[ToolDefinition] | None = None,
    ) -> AsyncIterator[StreamChunk]:
        async with build_client(self.config, headers=self._headers) as client:
            async with client.stream(
                "POST",
                "/messages",
                json=self._payload(
                    messages,
                    model=model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    tools=tools,
                    stream=True,
                ),
            ) as response:
                if response.status_code >= 400:
                    body = await response.aread()
                    raise Exception(body.decode())
                async for line in response.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    event = json.loads(line[6:])
                    if event.get("type") == "content_block_delta":
                        delta = event.get("delta", {})
                        if delta.get("type") == "text_delta":
                            yield StreamChunk(content=delta.get("text", ""))
                    elif event.get("type") == "message_stop":
                        yield StreamChunk(done=True)

    async def embed(self, texts: list[str], *, model: str) -> EmbeddingResponse:
        raise NotImplementedError(
            "Anthropic embeddings are not supported. Use provider='openai' for embeddings."
        )
