"""Tests for embedding client."""

from devai.core.embeddings import EmbeddingClient, MockEmbeddingClient


class TestMockEmbeddingClient:
    def test_embed_batch(self):
        client = MockEmbeddingClient(dimensions=32)
        vectors = client.embed(["hello", "world"])
        assert len(vectors) == 2
        assert len(vectors[0]) == 32

    def test_embed_one(self):
        client = MockEmbeddingClient()
        vector = client.embed_one("test")
        assert len(vector) == 64

    def test_similarity_identical(self):
        client = MockEmbeddingClient()
        assert client.similarity("same", "same") > 0.99

    def test_similarity_different(self):
        client = MockEmbeddingClient()
        score = client.similarity("abc", "xyz")
        assert -1.0 <= score <= 1.0


class TestEmbeddingClient:
    def test_close(self):
        client = EmbeddingClient(api_key="test-key")
        client.close()
