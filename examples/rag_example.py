"""RAG example for DevAI."""

from devai.core import MockLLMClient
from devai.rag import RAGChain, VectorStore, chunk_text

docs = [
    "Python uses indentation to define code blocks instead of braces.",
    "List comprehensions provide a concise way to create lists in Python.",
    "The asyncio module enables writing concurrent code using async/await syntax.",
    "Type hints were introduced in Python 3.5 and improved in later versions.",
    "pytest is the most popular testing framework for Python projects.",
]

# Chunk and index documents
all_chunks: list[str] = []
for doc in docs:
    all_chunks.extend(chunk_text(doc, chunk_size=200))

store = VectorStore()
store.add_documents(all_chunks)
print(f"Indexed {len(store)} document chunks")

# Query with RAG
client = MockLLMClient(
    default_response="Python uses indentation to define code blocks, not braces."
)
chain = RAGChain(client=client, store=store)

questions = [
    "How does Python handle code blocks?",
    "What testing framework is popular?",
]

for q in questions:
    print(f"\nQ: {q}")
    print(f"A: {chain.query(q)}")
