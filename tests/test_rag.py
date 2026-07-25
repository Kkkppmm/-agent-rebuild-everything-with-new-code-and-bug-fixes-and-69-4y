"""Tests for RAG module."""

import pytest

from devai import Chain, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.embeddings import MockEmbeddingClient
from devai.rag import RAGChain, VectorStore, chunk_text
from devai.rag.chunker import chunk_file


class TestChunker:
    def test_chunk_short_text(self):
        assert chunk_text("hello") == ["hello"]

    def test_chunk_with_overlap(self):
        text = "a" * 100 + "\n" + "b" * 100
        chunks = chunk_text(text, chunk_size=80, overlap=10)
        assert len(chunks) >= 2

    def test_chunk_file(self, tmp_path):
        path = tmp_path / "sample.txt"
        path.write_text("line one\nline two\nline three")
        chunks = chunk_file(str(path), chunk_size=10, overlap=2)
        assert chunks


class TestVectorStore:
    @pytest.mark.asyncio
    async def test_add_and_search(self):
        store = VectorStore(embedder=MockEmbeddingClient())
        await store.add(
            ["Python asyncio tutorial", "Rust ownership guide", "Python type hints"],
            metadata=[{"topic": "py"}, {"topic": "rust"}, {"topic": "py"}],
        )
        results = await store.search("Python async patterns", top_k=2)
        assert len(results) == 2
        assert results[0].score is not None
        assert "Python" in results[0].content

    def test_search_sync(self):
        store = VectorStore(embedder=MockEmbeddingClient())
        store.add_sync(["database indexing", "frontend css"])
        results = store.search_sync("sql indexes", top_k=1)
        assert len(results) == 1


class TestRAGChain:
    @pytest.mark.asyncio
    async def test_rag_run_with_mock_client(self):
        mock = MockLLMClient(responses=["Use asyncio.gather for concurrency."])
        rag = RAGChain(client=mock, config=DevAIConfig(api_key="test"))
        await rag.ingest(
            ["asyncio.gather runs awaitables concurrently."],
            metadata=[{"source": "docs"}],
        )
        answer = await rag.run("How do I run tasks concurrently?")
        assert "asyncio.gather" in answer
        assert len(mock.calls) == 1
        await rag.close()

    def test_chain_works_with_mock_client(self):
        mock = MockLLMClient(responses=["Review complete."])
        chain = Chain("Review: {code}", client=mock, config=DevAIConfig(api_key="test"))
        result = chain.run_sync(code="def foo(): pass")
        assert result == "Review complete."
