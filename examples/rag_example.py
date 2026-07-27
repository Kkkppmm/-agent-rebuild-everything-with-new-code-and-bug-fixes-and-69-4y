"""RAG example for querying documentation."""

from devai.core import MockLLMClient
from devai.rag import RAGChain, VectorStore, chunk_text

DOCUMENTATION = """
# DevAI Library

DevAI is a Python AI library for developers and programmers.

## Installation

Install with pip:
    pip install devai

For OpenAI support:
    pip install "devai[openai]"

## Quick Start

```python
from devai import CodeAssistant
from devai.core import MockLLMClient

assistant = CodeAssistant(client=MockLLMClient())
print(assistant.review("def foo(): pass"))
```

## Features

- Code review, debugging, and refactoring
- Agent framework with tool calling
- RAG for codebase Q&A
- CLI for quick tasks
"""


def main():
  chunks = chunk_text(DOCUMENTATION, chunk_size=200)
  store = VectorStore()
  store.add_documents(chunks)

  rag = RAGChain(client=MockLLMClient(), store=store)

  questions = [
    "How do I install DevAI?",
    "What features does DevAI provide?",
  ]

  for q in questions:
    print(f"\nQ: {q}")
    print(f"A: {rag.query(q)}")


if __name__ == "__main__":
  main()
