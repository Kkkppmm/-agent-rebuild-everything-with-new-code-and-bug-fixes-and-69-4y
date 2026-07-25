"""Embeddings helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class EmbeddingResult:
    """Embeddings for a batch of texts."""

    vectors: list[list[float]]
    model: str
    dimensions: int

    @classmethod
    def from_vectors(cls, vectors: list[list[float]], model: str) -> EmbeddingResult:
        dims = len(vectors[0]) if vectors else 0
        return cls(vectors=vectors, model=model, dimensions=dims)


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Cosine similarity between two vectors."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(x * x for x in b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def find_most_similar(
    query: list[float],
    candidates: list[list[float]],
    top_k: int = 5,
) -> list[tuple[int, float]]:
    """Return indices and scores of top-k most similar vectors."""
    scored = [(i, cosine_similarity(query, vec)) for i, vec in enumerate(candidates)]
    scored.sort(key=lambda x: x[1], reverse=True)
    return scored[:top_k]
