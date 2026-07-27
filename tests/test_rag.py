"""Tests for RAG module."""

from devai.core.client import MockLLMClient
from devai.rag import RAGChain, VectorStore, chunk_text


def test_chunk_text():
  text = "\n".join(["line " + str(i) for i in range(100)])
  chunks = chunk_text(text, chunk_size=200, overlap=20)
  assert len(chunks) > 1
  assert all(len(c) <= 250 for c in chunks)


def test_chunk_text_short():
  assert chunk_text("hello") == ["hello"]


def test_vector_store_add_and_search():
  store = VectorStore()
  store.add_documents(["Python is great", "JavaScript is async", "Rust is fast"])
  results = store.search_text("Python", top_k=1)
  assert len(results) == 1
  assert "Python" in results[0].content


def test_rag_chain_query():
  store = VectorStore()
  store.add_documents([
    "DevAI is a Python AI library for developers.",
    "Install with pip install devai.",
  ])
  client = MockLLMClient()
  rag = RAGChain(client=client, store=store)
  answer = rag.query("How do I install DevAI?")
  assert answer
