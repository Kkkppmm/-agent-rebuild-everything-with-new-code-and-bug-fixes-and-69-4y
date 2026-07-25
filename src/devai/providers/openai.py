"""OpenAI-compatible provider (OpenAI, Azure, Groq, etc.)."""

from __future__ import annotations

import json
from typing import AsyncIterator

from devai.config import DevAIConfig
from devai.exceptions import ConfigurationError
from devai.providers.base import build_client, parse_sse_line, request_json
from devai.types import (
    ChatResponse,
    EmbeddingResponse,
    Message,
    StreamChunk,
    ToolCall,
    ToolDefinition,
    Usage,
)


class OpenAIProvider:
    name = "openai"

    def __init__(self, config: DevAIConfig):
        self.config = config
        if not config.api_key:
            raise ConfigurationError(
                "OpenAI provider requires OPENAI_API_KEY or DEVAI_API_KEY."
            )
        self._headers = {
            "Authorization": f"Bearer {config.api_key}",
            "Content-Type": "application/json",
        }

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
        body: dict = {
            "model": model,
            "messages": [m.to_dict() for m in messages],
            "temperature": temperature,
            "stream": stream,
        }
        if max_tokens is not None:
            body["max_tokens"] = max_tokens
        if tools:
            body["tools"] = [t.to_openai_schema() for t in tools]
        return body

    def _parse_chat(self, data: dict, model: str) -> ChatResponse:
        choice = data["choices"][0]
        message = choice.get("message", {})
        tool_calls = []
        for tc in message.get("tool_calls") or []:
            fn = tc.get("function", {})
            args = fn.get("arguments", "{}")
            if isinstance(args, str):
                args = json.loads(args or "{}")
            tool_calls.append(
                ToolCall(id=tc["id"], name=fn["name"], arguments=args)
            )
        usage_data = data.get("usage", {})
        return ChatResponse(
            content=message.get("content") or "",
            model=data.get("model", model),
            provider=self.name,
            usage=Usage(
                prompt_tokens=usage_data.get("prompt_tokens", 0),
                completion_tokens=usage_data.get("completion_tokens", 0),
                total_tokens=usage_data.get("total_tokens", 0),
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
                "/chat/completions",
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
                "/chat/completions",
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
                    parsed = parse_sse_line(line)
                    if parsed is None:
                        continue
                    if parsed.get("done"):
                        yield StreamChunk(done=True)
                        break
                    choice = parsed["choices"][0]
                    delta = choice.get("delta", {})
                    yield StreamChunk(content=delta.get("content") or "")

    async def embed(self, texts: list[str], *, model: str) -> EmbeddingResponse:
        async with build_client(self.config, headers=self._headers) as client:
            data = await request_json(
                client,
                "POST",
                "/embeddings",
                provider=self.name,
                json_body={"model": model, "input": texts},
            )
        usage_data = data.get("usage", {})
        return EmbeddingResponse(
            embeddings=[item["embedding"] for item in data["data"]],
            model=data.get("model", model),
            provider=self.name,
            usage=Usage(
                prompt_tokens=usage_data.get("prompt_tokens", 0),
                total_tokens=usage_data.get("total_tokens", 0),
            ),
        )
