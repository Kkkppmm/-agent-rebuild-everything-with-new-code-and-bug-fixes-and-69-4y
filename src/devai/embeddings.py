"""Embedding utilities and vector operations."""

from __future__ import annotations

import math
from typing import Sequence

from devai.client import DevAI
from devai.types import EmbeddingResponse


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
  """Compute cosine similarity between two vectors."""
  dot = sum(x * y for x, y in zip(a, b))
  norm_a = math.sqrt(sum(x * x for x in a))
  norm_b = math.sqrt(sum(x * x for x in b))
  if norm_a == 0 or norm_b == 0:
    return 0.0
  return dot / (norm_a * norm_b)


def euclidean_distance(a: Sequence[float], b: Sequence[float]) -> float:
  """Compute Euclidean distance between two vectors."""
  return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


class Embedder:
  """Wrapper around DevAI embedding with similarity helpers."""

  def __init__(self, client: DevAI, model: str | None = None):
    self.client = client
    self.model = model

  async def embed(self, texts: list[str] | str) -> EmbeddingResponse:
    return await self.client.embed(texts, model=self.model)

  async def similarity(self, text_a: str, text_b: str) -> float:
    response = await self.embed([text_a, text_b])
    return cosine_similarity(response.embeddings[0], response.embeddings[1])

  async def most_similar(
    self,
    query: str,
    candidates: list[str],
    top_k: int = 1,
  ) -> list[tuple[str, float]]:
    """Find the most similar candidates to a query string."""
    all_texts = [query] + candidates
    response = await self.embed(all_texts)
    query_vec = response.embeddings[0]
    scores = [
      (candidates[i], cosine_similarity(query_vec, response.embeddings[i + 1]))
      for i in range(len(candidates))
    ]
    scores.sort(key=lambda x: x[1], reverse=True)
    return scores[:top_k]
