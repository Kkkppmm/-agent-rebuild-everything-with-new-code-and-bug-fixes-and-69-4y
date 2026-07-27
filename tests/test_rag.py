"""Tests for RAG module."""

from devai.core.client import MockLLMClient
from devai.rag import RAGChain, VectorStore, chunk_text


def test_chunk_text_basic():
  text = "paragraph one.\n\nparagraph two.\n\nparagraph three."
  chunks = chunk_text(text, chunk_size=30, overlap=5)
  assert len(chunks) >= 1
  assert all(isinstance(c, str) for c in chunks)


def test_chunk_text_empty():
  assert chunk_text("") == []
  assert chunk_text("   ") == []


def test_vector_store_add_and_search():
  store = VectorStore()
  store.add("Python is a programming language", topic="python")
  store.add("JavaScript runs in browsers", topic="js")
  results = store.search("Python programming")
  assert len(results) >= 1
  assert "Python" in results[0].content


def test_vector_store_add_documents():
  store = VectorStore()
  store.add_documents(["doc one about AI", "doc two about databases"])
  assert len(store) == 2


def test_rag_chain_query():
  client = MockLLMClient(default_response="DevAI is installed via pip.")
  store = VectorStore()
  store.add("Install DevAI with: pip install devai")
  rag = RAGChain(client=client, store=store)
  result = rag.query("How do I install DevAI?")
  assert result == "DevAI is installed via pip."
  assert "pip install devai" in client.calls[0][1].content
