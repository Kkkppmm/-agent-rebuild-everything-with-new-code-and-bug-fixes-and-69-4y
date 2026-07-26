# DevAI

A lightweight Python AI library built for developers and programmers. DevAI provides LLM clients, prompt templates, tool-calling agents, RAG pipelines, and a CLI — all with sensible defaults and zero vendor lock-in for local development.

## Features

- **LLM Clients** — OpenAI-compatible HTTP client plus a built-in mock for testing
- **Prompt Templates** — Developer-focused prompts for code review, debugging, security audits, and more
- **Tool Registry** — Register Python functions as LLM tools with automatic schema generation
- **Agents** — Tool-calling agent loop with `CoderAgent` for programming tasks
- **Chains** — Simple, sequential, and structured (Pydantic) output chains
- **RAG** — Text chunking, in-memory vector store, and retrieval-augmented generation
- **CLI** — `devai review`, `explain`, `debug`, `commit`, `tests`, `security`, `refactor`

## Installation

```bash
pip install -e .
# with dev dependencies
pip install -e ".[dev]"
# with OpenAI SDK (optional)
pip install -e ".[openai]"
```

## Quick Start

```python
from devai import DevAIConfig, MockLLMClient, Agent
from devai.prompts import CODE_REVIEW

config = DevAIConfig()
client = MockLLMClient(responses=["LGTM — no issues found."])
agent = Agent(client=client, config=config, system_prompt="You are a senior engineer.")

result = agent.run(CODE_REVIEW.format(code="def add(a, b): return a + b"))
print(result)
```

### Using a real LLM (OpenAI-compatible)

```python
from devai import DevAIConfig, LLMClient

config = DevAIConfig(
    api_key="sk-...",
    base_url="https://api.openai.com/v1",
    model="gpt-4o-mini",
)
client = LLMClient(config)
response = client.chat("Explain Python decorators in one paragraph.")
print(response)
```

### Structured output

```python
from pydantic import BaseModel
from devai.chains import StructuredChain
from devai import MockLLMClient, DevAIConfig

class Review(BaseModel):
  score: int
  summary: str

chain = StructuredChain(
    client=MockLLMClient(responses=['{"score": 9, "summary": "Clean code."}']),
    config=DevAIConfig(),
    output_model=Review,
    prompt="Review this code: {code}",
)
result = chain.run(code="def foo(): pass")
print(result.score, result.summary)
```

### RAG

```python
from devai import MockLLMClient, DevAIConfig
from devai.rag import VectorStore, RAGChain

store = VectorStore()
store.add_documents(["Python uses indentation.", "Lists are mutable sequences."])
rag = RAGChain(
    client=MockLLMClient(responses=["Python uses indentation for blocks."]),
    config=DevAIConfig(),
    store=store,
)
answer = rag.query("How does Python handle blocks?")
print(answer)
```

## CLI

```bash
# Review a file
devai review src/main.py

# Generate a commit message from staged diff
devai commit

# Explain code
devai explain "def fib(n): ..."

# Security review
devai security app.py
```

Set `DEVAI_API_KEY` and optionally `DEVAI_BASE_URL` / `DEVAI_MODEL` for live LLM calls. Without an API key the CLI uses the mock client.

## Development

```bash
pip install -e ".[dev]"
python -m pytest
ruff check src tests
```

## License

MIT
