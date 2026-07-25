"""OpenAI-compatible embedding client."""

from __future__ import annotations

import asyncio
import hashlib
import math
from typing import Any, Protocol

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import APIError, AuthenticationError, ConfigurationError, RateLimitError


class EmbeddingClientProtocol(Protocol):
    async def embed(self, texts: list[str], *, model: str | None = None) -> list[list[float]]: ...

    def embed_sync(self, texts: list[str], *, model: str | None = None) -> list[list[float]]: ...


class EmbeddingClient:
    """Async client for OpenAI-compatible embedding APIs."""

    def __init__(self, config: DevAIConfig | None = None, *, model: str = "text-embedding-3-small"):
        self.config = config or DevAIConfig()
        if not self.config.api_key:
            raise ConfigurationError(
                "API key required. Set OPENAI_API_KEY or pass api_key to DevAIConfig."
            )
        self.model = model
        self._client = httpx.AsyncClient(
            base_url=self.config.base_url.rstrip("/"),
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
                **self.config.extra_headers,
            },
            timeout=self.config.timeout,
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> EmbeddingClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def embed(self, texts: list[str], *, model: str | None = None) -> list[list[float]]:
        if not texts:
            return []
        payload = {"model": model or self.model, "input": texts}
        data = await self._request("/embeddings", payload)
        items = sorted(data["data"], key=lambda item: item["index"])
        return [item["embedding"] for item in items]

    def embed_sync(self, texts: list[str], *, model: str | None = None) -> list[list[float]]:
        return asyncio.run(self.embed(texts, model=model))

    async def _request(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = await self._client.post(path, json=payload)
        if response.status_code == 429:
            raise RateLimitError("Rate limit exceeded", status_code=429, body=response.text)
        if response.status_code == 401:
            raise AuthenticationError("Authentication failed", status_code=401, body=response.text)
        if response.status_code >= 400:
            raise APIError(
                f"API error: {response.status_code}",
                status_code=response.status_code,
                body=response.text,
            )
        return response.json()


class MockEmbeddingClient:
    """Deterministic embedding client for tests and offline RAG."""

    def __init__(self, dimensions: int = 64):
        self.dimensions = dimensions

    async def embed(self, texts: list[str], *, model: str | None = None) -> list[list[float]]:
        return [self._vectorize(text) for text in texts]

    def embed_sync(self, texts: list[str], *, model: str | None = None) -> list[list[float]]:
        return [self._vectorize(text) for text in texts]

    async def close(self) -> None:
        return None

    def _vectorize(self, text: str) -> list[float]:
        digest = hashlib.sha256(text.encode()).digest()
        values = [((digest[i % len(digest)] / 255.0) * 2 - 1) for i in range(self.dimensions)]
        norm = math.sqrt(sum(v * v for v in values)) or 1.0
        return [v / norm for v in values]


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors."""
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)
