"""RAG example for DevAI."""

from devai import MockLLMClient
from devai.rag import RAGChain, VectorStore, chunk_text

readme = """
# DevAI

DevAI is a Python AI library for developers.
Install with: pip install devai

Features include code review, debugging, agents, and RAG.
"""

docs = chunk_text(readme, chunk_size=100, overlap=20)
store = VectorStore()
store.add_documents(docs)

chain = RAGChain(client=MockLLMClient(), store=store)
answer = chain.query("How do I install DevAI?")
print(answer)
