"""Embedding client for DevAI."""

from __future__ import annotations

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import APIError


class EmbeddingClient:
    """OpenAI-compatible embedding client."""

    def __init__(self, config: DevAIConfig | None = None):
        self.config = config or DevAIConfig.from_env()

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for a list of texts."""
        with httpx.Client(timeout=self.config.timeout) as client:
            resp = client.post(
                f"{self.config.base_url}/embeddings",
                headers={
                    "Authorization": f"Bearer {self.config.require_api_key()}",
                    "Content-Type": "application/json",
                },
                json={"model": self.config.embedding_model, "input": texts},
            )
            if resp.status_code != 200:
                raise APIError(
                    f"Embedding request failed: {resp.status_code}",
                    status_code=resp.status_code,
                    body=resp.text,
                )
            data = resp.json()
            return [item["embedding"] for item in sorted(data["data"], key=lambda x: x["index"])]

    def embed_one(self, text: str) -> list[float]:
        return self.embed([text])[0]


class MockEmbeddingClient:
    """Deterministic mock embedding client for testing."""

    def __init__(self, dimensions: int = 8):
        self.dimensions = dimensions

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._hash_embed(t) for t in texts]

    def embed_one(self, text: str) -> list[float]:
        return self._hash_embed(text)

    def _hash_embed(self, text: str) -> list[float]:
        h = hash(text)
        return [((h >> (i * 8)) & 0xFF) / 255.0 for i in range(self.dimensions)]
