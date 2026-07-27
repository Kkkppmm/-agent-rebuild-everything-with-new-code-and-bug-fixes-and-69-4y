# DevAI

A Python AI library built for developers and programmers. DevAI provides a clean, provider-agnostic interface for LLM-powered coding workflows — code review, debugging, refactoring, test generation, agents with tool calling, RAG, and more.

## Features

- **Provider-agnostic LLM client** — OpenAI, Anthropic, or bring your own
- **CodeAssistant** — High-level API for common dev tasks
- **Agents** — Tool-calling agents for autonomous coding workflows
- **Chains** — Composable prompt chains with structured output
- **RAG** — Retrieval-augmented generation over your codebase
- **CLI** — Quick command-line access to all features
- **Mock client** — Test without API keys

## Installation

```bash
pip install devai

# With OpenAI support
pip install "devai[openai]"

# With all providers + dev tools
pip install "devai[all,dev]"
```

## Quick Start

```python
from devai import CodeAssistant, DevAIConfig
from devai.core import MockLLMClient

# Use mock client for testing (no API key needed)
client = MockLLMClient()
assistant = CodeAssistant(client=client)

# Review code
review = assistant.review("""
def add(a, b):
    return a + b
""")
print(review)

# Explain code
explanation = assistant.explain("async def fetch(url): ...")

# Debug an error
fix = assistant.debug(
    code="result = items[10]",
    error="IndexError: list index out of range",
)
```

## With a Real LLM Provider

```python
from devai import CodeAssistant, DevAIConfig
from devai.core import LLMClient

config = DevAIConfig(
    provider="openai",
    model="gpt-4o-mini",
    api_key="sk-...",
)
client = LLMClient(config)
assistant = CodeAssistant(client=client)

print(assistant.review(open("app.py").read()))
```

## Agents with Tools

```python
from devai.agents import CoderAgent
from devai.core import MockLLMClient
from devai.tools import ToolRegistry, read_file, search_code

registry = ToolRegistry()
registry.register(read_file)
registry.register(search_code)

agent = CoderAgent(client=MockLLMClient(), tools=registry)
result = agent.run("Find all TODO comments in the project")
```

## RAG over Your Codebase

```python
from devai.rag import RAGChain, VectorStore, chunk_text
from devai.core import MockLLMClient

docs = chunk_text(open("README.md").read())
store = VectorStore()
store.add_documents(docs)

rag = RAGChain(client=MockLLMClient(), store=store)
answer = rag.query("How do I install this library?")
```

## CLI

```bash
# Review a file
devai review app.py

# Explain code
devai explain "def fib(n): ..."

# Generate commit message from diff
devai commit

# Run security review
devai security src/

# Interactive agent
devai agent "Refactor the auth module"
```

## Configuration

Set environment variables or pass a `DevAIConfig`:

| Variable | Description |
|----------|-------------|
| `DEVAI_PROVIDER` | `openai`, `anthropic`, or `mock` |
| `DEVAI_MODEL` | Model name (e.g. `gpt-4o-mini`) |
| `DEVAI_API_KEY` | API key for the provider |
| `DEVAI_BASE_URL` | Custom API base URL |
| `DEVAI_MAX_TOKENS` | Max tokens per response (default: 4096) |
| `DEVAI_TEMPERATURE` | Sampling temperature (default: 0.2) |

## Development

```bash
pip install -e ".[dev]"
python -m pytest
ruff check src tests
```

## License

MIT
