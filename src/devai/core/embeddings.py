"""Embedding client for semantic search and RAG."""

from __future__ import annotations

import math
from typing import Any

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import LLMError


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(x * x for x in b))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


class EmbeddingClient:
    """OpenAI-compatible embedding API client."""

    def __init__(
        self,
        config: DevAIConfig | None = None,
        *,
        model: str = "text-embedding-3-small",
        **kwargs: Any,
    ) -> None:
        if config is None:
            config = DevAIConfig(**kwargs)
        self.config = config
        self.model = model
        self._client: httpx.Client | None = None

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.config.base_url,
                timeout=self.config.timeout,
            )
        return self._client

    def _headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
        headers.update(self.config.extra_headers)
        return headers

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Embed a batch of texts."""
        if not texts:
            return []

        payload = {"model": self.model, "input": texts}
        response = self._get_client().post(
            "/embeddings",
            json=payload,
            headers=self._headers(),
        )
        if response.status_code >= 400:
            raise LLMError(f"Embedding API error {response.status_code}: {response.text}")

        data = response.json()
        items = sorted(data.get("data", []), key=lambda item: item.get("index", 0))
        return [item["embedding"] for item in items]

    def embed_one(self, text: str) -> list[float]:
        """Embed a single text."""
        return self.embed([text])[0]

    def similarity(self, a: str, b: str) -> float:
        """Cosine similarity between two texts."""
        vectors = self.embed([a, b])
        return _cosine_similarity(vectors[0], vectors[1])

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None


class MockEmbeddingClient:
    """Deterministic mock embeddings for testing without an API key."""

    def __init__(self, dimensions: int = 64) -> None:
        self.dimensions = dimensions
        self.model = "mock-embedding"

    def _hash_vector(self, text: str) -> list[float]:
        seed = sum(ord(c) * (i + 1) for i, c in enumerate(text))
        vector = []
        for i in range(self.dimensions):
            value = math.sin(seed * (i + 1) * 0.1) + math.cos(seed * (i + 2) * 0.07)
            vector.append(value)
        mag = math.sqrt(sum(v * v for v in vector)) or 1.0
        return [v / mag for v in vector]

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._hash_vector(text) for text in texts]

    def embed_one(self, text: str) -> list[float]:
        return self._hash_vector(text)

    def similarity(self, a: str, b: str) -> float:
        return _cosine_similarity(self.embed_one(a), self.embed_one(b))
