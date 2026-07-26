# DevAI

A Python AI library built for developers and programmers. DevAI provides LLM clients, developer-focused prompts, code tools, agents, chains, RAG, and a CLI — everything you need to build AI-powered developer tools.

## Features

- **LLM Client** — OpenAI-compatible API client with streaming, tool calling, JSON mode, and embeddings
- **Mock Client** — Test without API keys using deterministic mock responses
- **Developer Prompts** — 13+ ready-made templates (code review, debug, commit messages, security review, etc.)
- **Code Tools** — Lint, explain, search, complexity analysis, git diff, file reading
- **Agents** — Tool-calling agent loop with a pre-built `CoderAgent`
- **Chains** — Compose LLM workflows with sequential and structured output chains
- **RAG** — Chunk text, vector store, and retrieval-augmented generation
- **Memory** — Token-aware conversation memory with sliding window
- **CLI** — Command-line tools for review, debug, commit, tests, security, and refactor

## Installation

```bash
pip install -e .
# with dev dependencies
pip install -e ".[dev]"
```

## Quick Start

### Basic LLM Usage

```python
from devai import LLMClient, DevAIConfig, Message, Role

config = DevAIConfig(api_key="sk-...", model="gpt-4o-mini")
client = LLMClient(config)

response = client.complete([
    Message(role=Role.SYSTEM, content="You are a helpful coding assistant."),
    Message(role=Role.USER, content="Explain Python decorators."),
])
print(response.content)
```

### Mock Client (No API Key)

```python
from devai import MockLLMClient, Message, Role

client = MockLLMClient(responses=["Decorators wrap functions..."])
response = client.complete([Message(role=Role.USER, content="Explain decorators")])
print(response.content)
```

### Developer Prompts

```python
from devai.prompts import dev_prompts

prompt = dev_prompts.CODE_REVIEW.format(
    code="def add(a, b): return a + b",
    language="python",
)
```

### Coder Agent

```python
from devai import CoderAgent, MockLLMClient

agent = CoderAgent(MockLLMClient(responses=["Code looks good!"]))
print(agent.review("def foo(): pass"))
```

### Chains

```python
from devai import Chain, MockLLMClient

client = MockLLMClient(responses=["Optimized query"])
chain = Chain(client, "Optimize this SQL: {query}")
result = chain.run(query="SELECT * FROM users")
```

### RAG

```python
from devai import MockLLMClient
from devai.rag import RAGChain, VectorStore

client = MockLLMClient(responses=["Based on the docs..."])
rag = RAGChain(client, VectorStore())
rag.index(["Your documentation text here..."])
answer = rag.query("How do I configure the API?")
```

## CLI

```bash
# Review code (uses mock LLM without API key)
devai --mock review --code "def foo(): pass"

# Explain code structure (local analysis)
devai explain --code "class Foo: pass" --local-only

# Generate commit message from git diff
devai --mock commit

# Security review
devai --mock security --file app.py

# Generate tests
devai --mock tests --file mymodule.py

# Debug an error
devai --mock debug --code "print(x)" --error "NameError: x is not defined"
```

## Configuration

Set environment variables or use `DevAIConfig`:

| Variable | Default | Description |
|----------|---------|-------------|
| `DEVAI_API_KEY` | — | API key (falls back to `OPENAI_API_KEY`) |
| `DEVAI_BASE_URL` | `https://api.openai.com/v1` | API base URL |
| `DEVAI_MODEL` | `gpt-4o-mini` | Chat model |
| `DEVAI_TEMPERATURE` | `0.7` | Sampling temperature |
| `DEVAI_MAX_TOKENS` | `4096` | Max response tokens |

## Project Structure

```
src/devai/
├── core/       # LLM client, config, models, exceptions
├── prompts/    # Prompt templates for developers
├── tools/      # Code utilities and tool registry
├── agents/     # Agent with tool-calling loop
├── chains/     # Chain compositions
├── memory/     # Conversation memory
├── rag/        # Retrieval-augmented generation
├── output/     # Structured output parsing
├── utils/      # Token estimation, code extraction
└── cli.py      # Command-line interface
```

## Development

```bash
pip install -e ".[dev]"
python -m pytest
ruff check src/ tests/
```

## License

MIT
