"""Tests for RAG module."""

import math

import pytest

from devai.rag import VectorStore, chunk_text, cosine_similarity


class TestChunkText:
    def test_basic(self):
        text = "a" * 1000
        chunks = chunk_text(text, chunk_size=300, overlap=50)
        assert len(chunks) >= 3
        assert all(len(c) <= 300 for c in chunks)

    def test_invalid_chunk_size(self):
        with pytest.raises(ValueError):
            chunk_text("hi", chunk_size=0)

    def test_invalid_overlap(self):
        with pytest.raises(ValueError):
            chunk_text("hi", chunk_size=100, overlap=100)


class TestCosineSimilarity:
    def test_identical(self):
        v = [1.0, 2.0, 3.0]
        assert math.isclose(cosine_similarity(v, v), 1.0)

    def test_orthogonal(self):
        assert math.isclose(cosine_similarity([1, 0], [0, 1]), 0.0)

    def test_zero_vector(self):
        assert cosine_similarity([0, 0], [1, 1]) == 0.0


class TestVectorStore:
    def test_add_and_search(self):
        store = VectorStore()
        store.add("hello world", [1.0, 0.0, 0.0])
        store.add("goodbye world", [0.0, 1.0, 0.0])
        results = store.search([0.9, 0.1, 0.0], top_k=1)
        assert len(results) == 1
        assert "hello" in results[0].content

    def test_add_many(self):
        store = VectorStore()
        store.add_many(
            ["a", "b"],
            [[1, 0], [0, 1]],
        )
        assert len(store) == 2

    def test_clear(self):
        store = VectorStore()
        store.add("x", [1.0])
        store.clear()
        assert len(store) == 0
