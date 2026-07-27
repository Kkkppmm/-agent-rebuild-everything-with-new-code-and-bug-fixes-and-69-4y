"""RAG example over documentation."""

from devai import DevAIConfig
from devai.rag import RAGChain, VectorStore, chunk_text

docs = """
# DevAI Installation

Install DevAI with pip: pip install devai

For development: pip install -e ".[dev]"

# Features

DevAI provides code review, debugging, refactoring, agents, and RAG.
Use DevAIConfig.mock() to test without an API key.
"""

config = DevAIConfig.mock()
store = VectorStore(config=config)
store.add_documents(chunk_text(docs, metadata={"source": "readme"}))

rag = RAGChain(store=store, config=config)
answer = rag.query("How do I install DevAI?")
print(answer)
