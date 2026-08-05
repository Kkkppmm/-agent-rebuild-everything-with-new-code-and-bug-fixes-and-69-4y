"""Tests for semantic RAG."""

from devai.core.embeddings import MockEmbeddingClient
from devai.core import MockLLMClient
from devai.rag.semantic import SemanticRAGChain, SemanticVectorStore


class TestSemanticVectorStore:
    def test_add_and_search(self):
        store = SemanticVectorStore(MockEmbeddingClient())
        store.add_texts(
            [
                "Python is a programming language",
                "JavaScript runs in browsers",
            ]
        )
        results = store.search("python coding", top_k=1)
        assert len(results) == 1
        assert "Python" in results[0].content

    def test_chunked_add(self):
        store = SemanticVectorStore(MockEmbeddingClient())
        long_text = "line one\nline two\nline three\n" * 50
        store.add_texts([long_text], chunk=True, chunk_size=100)
        assert len(store) > 1


class TestSemanticRAGChain:
    def test_query(self):
        client = MockLLMClient(default_response="answer")
        store = SemanticVectorStore(MockEmbeddingClient())
        store.add_texts(["DevAI is a Python AI library"])
        chain = SemanticRAGChain(client, store)
        assert chain.query("What is DevAI?") == "answer"
