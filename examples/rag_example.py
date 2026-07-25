"""RAG example — index documents and ask questions."""

from devai import DevAI, RAGPipeline

ai = DevAI.mock()
rag = RAGPipeline(chunk_size=200)

docs = [
    "DevAI is a Python library for developers building AI applications.",
    "It supports chat, embeddings, tool calling, and RAG out of the box.",
    "Use DevAI.mock() to try it without an API key.",
]

rag.index(ai, docs)
context = rag.build_context(ai, "How do I try DevAI without an API key?")
print("Retrieved context:")
print(context)
print()

response = rag.ask(ai, "What features does DevAI support?")
print("Answer:", response.content)
