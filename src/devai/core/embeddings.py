"""Embedding client for vector operations."""

from __future__ import annotations

from typing import Any

import httpx

from devai.core.config import DevAIConfig
from devai.core.exceptions import LLMError


class EmbeddingClient:
    """OpenAI-compatible embedding client."""

    def __init__(self, config: DevAIConfig | None = None, **kwargs: Any) -> None:
        if config is None:
            config = DevAIConfig.from_env()
        self.config = config.with_overrides(**kwargs)
        self._client = httpx.Client(
            base_url=self.config.base_url,
            headers=self._headers(),
            timeout=self.config.timeout,
        )

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers

    def embed(self, texts: list[str], *, model: str | None = None) -> list[list[float]]:
        """Generate embeddings for a list of texts."""
        response = self._client.post(
            "/embeddings",
            json={
                "model": model or self.config.embedding_model,
                "input": texts,
            },
        )
        if response.status_code >= 400:
            raise LLMError(f"Embedding error {response.status_code}: {response.text}")
        data = response.json()
        sorted_data = sorted(data["data"], key=lambda x: x["index"])
        return [item["embedding"] for item in sorted_data]

    def embed_one(self, text: str, *, model: str | None = None) -> list[float]:
        """Generate embedding for a single text."""
        return self.embed([text], model=model)[0]

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> EmbeddingClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
