"""RAG over documents example."""

from devai.core.client import MockLLMClient
from devai.rag import RAGChain, VectorStore, chunk_text

DOCUMENT = """
# DevAI Installation Guide

Install DevAI using pip:

    pip install devai

For development, install with dev dependencies:

    pip install -e ".[dev]"

## Configuration

Set your OpenAI API key:

    export OPENAI_API_KEY=sk-...

Or use the mock client for testing without an API key.
"""


def main():
  chunks = chunk_text(DOCUMENT, chunk_size=200, overlap=20)
  store = VectorStore()
  store.add_documents(chunks)

  client = MockLLMClient(
    default_response="Install DevAI with: pip install devai"
  )
  rag = RAGChain(client=client, store=store)

  questions = [
    "How do I install DevAI?",
    "How do I set up the API key?",
  ]

  for q in questions:
    print(f"Q: {q}")
    print(f"A: {rag.query(q)}\n")


if __name__ == "__main__":
  main()
