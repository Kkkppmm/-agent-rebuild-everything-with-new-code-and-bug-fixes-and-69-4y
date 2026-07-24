# DevAI

A Python AI library built for developers and programmers. DevAI provides LLM clients, pre-built dev prompts, tool-calling agents, RAG chains, and a CLI for common coding workflows.

## Features

- **LLM Client** — OpenAI-compatible API with streaming, JSON mode, retries, and tool calling
- **Mock Client** — Test without API keys
- **Dev Prompts** — 13+ templates for code review, debugging, commits, security, SQL, and more
- **Agents** — `Agent` and `CoderAgent` with tool-calling loops
- **Tools** — Code analysis utilities (lint, complexity, search, git diff)
- **Chains** — Sequential and structured (Pydantic) output chains
- **RAG** — Chunking, vector store, and retrieval-augmented generation
- **Memory** — Conversation history with windowing
- **CLI** — `devai review`, `explain`, `debug`, `commit`, `security`, `refactor`, `tests`

## Installation

```bash
pip install -e ".[dev]"
```

## Quick Start

```python
from devai import MockLLMClient, Message, Role
from devai.agents import CoderAgent
from devai.prompts import CODE_REVIEW

# Use mock client for testing (no API key needed)
client = MockLLMClient(responses=["Looks good! No issues found."])

# Simple completion
response = client.complete([
    Message(role=Role.USER, content="Explain list comprehensions"),
])
print(response.content)

# Code review with prompts
prompt = CODE_REVIEW.format(language="python", code="def add(a, b): return a + b")
response = client.complete([Message(role=Role.USER, content=prompt)])

# Coder agent with built-in tools
agent = CoderAgent(client)
result = agent.explain("def fib(n): return n if n < 2 else fib(n-1) + fib(n-2)")
```

## Using a Real LLM

```python
from devai import LLMClient, DevAIConfig

config = DevAIConfig.from_env()  # reads OPENAI_API_KEY
client = LLMClient(config)
response = client.complete([...])
```

Set your API key:

```bash
export OPENAI_API_KEY=sk-...
```

## CLI

```bash
# Review a file
devai review -f mycode.py

# Explain code from stdin
cat script.py | devai explain

# Generate commit message
devai commit

# Debug with error message
devai debug -f app.py -e "NameError: name 'x' is not defined"

# Security review
devai security -f auth.py

# Generate unit tests
devai tests -f utils.py --framework pytest

# Use mock mode (no API key)
devai --mock review -c "def foo(): pass"
```

## RAG Example

```python
from devai import MockLLMClient
from devai.rag import RAGChain

client = MockLLMClient(responses=["Based on the docs, use pip install devai."])
rag = RAGChain(client)
rag.add_documents(["DevAI is installed via pip install devai."])
answer = rag.run("How do I install DevAI?")
```

## Structured Output

```python
from pydantic import BaseModel
from devai import MockLLMClient
from devai.chains import StructuredChain

class ReviewResult(BaseModel):
    score: int
    issues: list[str]

client = MockLLMClient(responses=['{"score": 8, "issues": ["missing types"]}'])
chain = StructuredChain(
    client,
    "Review this code: {code}",
    ReviewResult,
)
result = chain.run(code="def foo(): pass")
print(result.score, result.issues)
```

## Project Structure

```
src/devai/
├── core/       # LLM client, config, models, exceptions
├── prompts/    # Prompt templates for dev workflows
├── tools/      # Tool registry and code utilities
├── agents/     # Agent and CoderAgent
├── chains/     # Chain abstractions
├── memory/     # Conversation memory
├── rag/        # RAG pipeline
├── output/     # Structured parsing
├── utils/      # Token and code helpers
└── cli.py      # Command-line interface
```

## Development

```bash
pip install -e ".[dev]"
python -m pytest
ruff check src tests
```

## License

MIT
