"""Tests for DevAI RAG."""

import pytest

from devai.core import MockLLMClient
from devai.rag import RAGChain, VectorStore, chunk_text


class TestChunkText:
    def test_basic_chunking(self):
        text = "Paragraph one.\n\nParagraph two.\n\nParagraph three."
        chunks = chunk_text(text, chunk_size=30, overlap=5)
        assert len(chunks) >= 1

    def test_empty_text(self):
        assert chunk_text("") == []
        assert chunk_text("   ") == []

    def test_single_paragraph(self):
        chunks = chunk_text("Short text", chunk_size=500)
        assert len(chunks) == 1


class TestVectorStore:
    def test_add_and_search(self):
        store = VectorStore()
        store.add_documents([
            "Python is a programming language",
            "JavaScript runs in browsers",
            "Python has great libraries for data science",
        ])
        assert len(store) == 3
        results = store.search("Python programming")
        assert len(results) > 0
        assert "Python" in results[0].content

    def test_empty_search(self):
        store = VectorStore()
        assert store.search("anything") == []

    def test_metadata(self):
        store = VectorStore()
        store.add_documents(["doc1"], metadata=[{"source": "test"}])
        assert store.documents[0].metadata["source"] == "test"


class TestRAGChain:
    def test_query(self):
        store = VectorStore()
        store.add_documents(["Python uses indentation for blocks."])
        client = MockLLMClient(default_response="Python uses indentation.")
        chain = RAGChain(client, store)
        result = chain.query("How does Python handle blocks?")
        assert "indentation" in result.lower()

    @pytest.mark.asyncio
    async def test_aquery(self):
        store = VectorStore()
        store.add_documents(["asyncio enables concurrent programming."])
        client = MockLLMClient(default_response="asyncio is for concurrency.")
        chain = RAGChain(client, store)
        result = await chain.aquery("What is asyncio?")
        assert "asyncio" in result.lower()
