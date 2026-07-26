"""Simple in-memory vector store with cosine similarity."""

import hashlib
import math
from typing import Any, Optional


def _tokenize(text: str) -> dict[str, float]:
    words = text.lower().split()
    counts: dict[str, float] = {}
    for word in words:
        counts[word] = counts.get(word, 0) + 1.0
    return counts


def _cosine_similarity(a: dict[str, float], b: dict[str, float]) -> float:
    dot = sum(a.get(k, 0) * b.get(k, 0) for k in set(a) | set(b))
    mag_a = math.sqrt(sum(v * v for v in a.values()))
    mag_b = math.sqrt(sum(v * v for v in b.values()))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


class VectorStore:
    """Lightweight in-memory vector store using bag-of-words embeddings."""

    def __init__(self) -> None:
        self._documents: list[dict[str, Any]] = []

    def add(self, text: str, metadata: Optional[dict[str, Any]] = None) -> str:
        doc_id = hashlib.md5(text.encode()).hexdigest()[:12]
        self._documents.append({
            "id": doc_id,
            "text": text,
            "vector": _tokenize(text),
            "metadata": metadata or {},
        })
        return doc_id

    def add_batch(self, texts: list[str], metadatas: Optional[list[dict]] = None) -> list[str]:
        ids = []
        for i, text in enumerate(texts):
            meta = metadatas[i] if metadatas else None
            ids.append(self.add(text, meta))
        return ids

    def search(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        query_vec = _tokenize(query)
        scored = []
        for doc in self._documents:
            score = _cosine_similarity(query_vec, doc["vector"])
            scored.append({
                "id": doc["id"],
                "text": doc["text"],
                "score": score,
                "metadata": doc["metadata"],
            })
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:top_k]

    def delete(self, doc_id: str) -> bool:
        for i, doc in enumerate(self._documents):
            if doc["id"] == doc_id:
                self._documents.pop(i)
                return True
        return False

    def clear(self) -> None:
        self._documents.clear()

    def __len__(self) -> int:
        return len(self._documents)
