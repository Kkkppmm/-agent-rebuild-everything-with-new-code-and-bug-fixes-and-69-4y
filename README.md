# DevAI

A lightweight Python AI library built for developers and programmers. DevAI provides LLM clients, prompt templates, tool-calling agents, RAG pipelines, and a CLI — all with zero vendor lock-in and a mock client for testing.

## Features

- **LLM Clients** — OpenAI-compatible HTTP client with streaming, JSON mode, and automatic retries
- **Mock Client** — Deterministic responses for unit tests without API keys
- **Prompt Templates** — Pre-built templates for code review, debugging, security audits, and more
- **Tool Registry** — Register Python functions as LLM tools with automatic schema generation
- **Agents** — Tool-calling agent loop with `CoderAgent` for programming tasks
- **Chains** — Sequential and structured (Pydantic) output chains
- **RAG** — Text chunking, in-memory vector store, and retrieval-augmented generation
- **CLI** — `devai review`, `explain`, `debug`, `commit`, `tests`, `security`, `refactor`

## Installation

```bash
pip install -e .
# with dev dependencies
pip install -e ".[dev]"
```

## Quick Start

```python
from devai import DevAIConfig, MockLLMClient, Agent
from devai.prompts import CODE_REVIEW

config = DevAIConfig(api_key="sk-...", model="gpt-4o-mini")
client = MockLLMClient()  # swap for LLMClient in production

response = client.chat(
    messages=[{"role": "user", "content": CODE_REVIEW.format(code="def add(a, b): return a + b")}],
)
print(response.content)
```

### Agent with Tools

```python
from devai.agents import CoderAgent
from devai.tools import ToolRegistry, read_file, lint_python

registry = ToolRegistry()
registry.register(read_file)
registry.register(lint_python)

agent = CoderAgent(client=client, tools=registry)
result = agent.run("Review the code in main.py")
print(result)
```

### RAG Pipeline

```python
from devai.rag import chunk_text, VectorStore, RAGChain

chunks = chunk_text(document_text, chunk_size=500)
store = VectorStore()
store.add_documents(chunks)
rag = RAGChain(client=client, vector_store=store)
answer = rag.query("How does authentication work?")
```

## CLI

```bash
# Code review
devai review --file src/app.py

# Generate commit message from staged diff
devai commit

# Explain code
devai explain --file utils.py

# Debug an error
devai debug --error "TypeError: unsupported operand"

# Generate tests
devai tests --file calculator.py

# Security review
devai security --file api.py

# Refactor suggestions
devai refactor --file legacy.py
```

Set `OPENAI_API_KEY` and optionally `DEVAI_MODEL` (default: `gpt-4o-mini`).

## Configuration

| Variable | Description | Default |
|---|---|---|
| `OPENAI_API_KEY` | API key for LLM provider | — |
| `DEVAI_MODEL` | Model name | `gpt-4o-mini` |
| `DEVAI_BASE_URL` | API base URL | `https://api.openai.com/v1` |
| `DEVAI_MAX_RETRIES` | Retry count on failure | `3` |
| `DEVAI_TIMEOUT` | Request timeout (seconds) | `60` |

## Development

```bash
pip install -e ".[dev]"
python -m pytest
ruff check src tests
```

## License

MIT
