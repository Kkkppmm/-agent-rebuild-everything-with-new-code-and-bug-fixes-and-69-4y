# DevAI

A lightweight Python AI library for developers and programmers. Chat with LLMs, generate embeddings, run tool-calling agents, and build RAG pipelines — with a simple API and no vendor lock-in.

## Features

- **Simple API** — `DevAI().chat("Hello")` works out of the box
- **Provider agnostic** — OpenAI-compatible APIs, Ollama, Azure, vLLM, and a built-in mock provider
- **Streaming** — sync and async token streaming
- **Embeddings** — batch embedding with cosine similarity utilities
- **Tool calling** — decorator-based tool registry with automatic JSON schema generation
- **RAG** — document chunking, in-memory vector store, and retrieval-augmented queries
- **Prompt templates** — reusable prompts with variable substitution
- **Conversation sessions** — stateful chat with history management
- **Retries** — automatic exponential backoff on transient API errors
- **Typed** — full type hints for IDE support

## Installation

```bash
pip install devai
```

Or install from source:

```bash
pip install -e ".[dev]"
```

## Quick Start

No API key required — uses the mock provider by default when no key is set:

```python
from devai import DevAI

ai = DevAI.mock()
print(ai.chat("Hello, DevAI!").content)
```

### OpenAI

```python
import os
from devai import DevAI

ai = DevAI.openai(api_key=os.environ["OPENAI_API_KEY"])
print(ai.chat("Explain list comprehensions in Python").content)
```

### Local Ollama

```python
from devai import DevAI

ai = DevAI.ollama(model="llama3.2")
print(ai.chat("Write a haiku about code").content)
```

### Streaming

```python
for token in ai.chat_stream("Tell me a joke"):
    print(token, end="", flush=True)
```

### Async

```python
import asyncio
from devai import DevAI

async def main():
    ai = DevAI.mock()
    response = await ai.chat_async("Hello async!")
    print(response.content)

asyncio.run(main())
```

## Conversation Sessions

```python
ai = DevAI.mock()
session = ai.session(system="You are a senior Python developer.")

session.complete(ai, "How do I read a JSON file?")
session.complete(ai, "Can you show an example?")

for msg in session.messages:
    print(f"{msg.role}: {msg.content[:80]}...")
```

## Embeddings

```python
from devai.embeddings import cosine_similarity

vectors = ai.embed(["Python is great", "Java is also great"])
similarity = cosine_similarity(vectors[0], vectors[1])
print(f"Similarity: {similarity:.3f}")
```

## Tool Calling

```python
from devai import DevAI, ToolRegistry

registry = ToolRegistry()

@registry.register(description="Add two numbers")
def add(a: int, b: int) -> int:
    return a + b

ai = DevAI.openai()
ai.tools = registry
response = ai.run_with_tools("What is 17 + 25?")
print(response.content)
```

## RAG (Retrieval-Augmented Generation)

```python
from devai import DevAI, RAGPipeline

ai = DevAI.mock()
rag = RAGPipeline()

rag.index(ai, [
    "DevAI supports chat, embeddings, and RAG.",
    "Use DevAI.mock() without an API key.",
])

answer = rag.ask(ai, "What can DevAI do?")
print(answer.content)
```

## Prompt Templates

```python
from devai import PromptTemplate

tpl = PromptTemplate("Write a {language} function to {task}.")
prompt = tpl.format(language="Python", task="merge two sorted lists")
print(ai.chat(prompt).content)
```

## Configuration

| Environment Variable | Description |
|---------------------|-------------|
| `OPENAI_API_KEY` | API key for OpenAI-compatible providers |
| `DEVAI_API_KEY` | Alternative API key variable |
| `DEVAI_BASE_URL` | Custom base URL (e.g. `http://localhost:11434/v1` for Ollama) |

## Project Structure

```
devai/
├── client.py       # Main DevAI client
├── chat.py         # Messages and ChatSession
├── embeddings.py   # Embedding utilities
├── tools.py        # Tool registry and execution
├── rag.py          # RAG pipeline and vector store
├── prompts.py      # Prompt templates
├── providers/      # OpenAI, Mock providers
└── utils/          # Retry logic
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check devai tests
```

## License

MIT
