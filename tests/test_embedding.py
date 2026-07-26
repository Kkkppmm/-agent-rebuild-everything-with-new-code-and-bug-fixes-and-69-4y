"""Tests for DevAI embedding client."""

from devai.core.embedding import MockEmbeddingClient


def test_mock_embedding():
    client = MockEmbeddingClient(dimensions=4)
    emb = client.embed_one("hello")
    assert len(emb) == 4
    assert all(0 <= v <= 1 for v in emb)


def test_mock_embedding_batch():
    client = MockEmbeddingClient()
    embs = client.embed(["hello", "world"])
    assert len(embs) == 2
    assert embs[0] != embs[1]
