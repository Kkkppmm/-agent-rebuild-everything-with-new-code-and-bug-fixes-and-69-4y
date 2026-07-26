# DevAI

A Python AI library built for developers and programmers. DevAI provides LLM clients, prompt templates, tool-calling agents, RAG pipelines, and a CLI for common dev workflows.

## Features

- **LLM Client** — OpenAI-compatible client with streaming, retries, JSON mode, and async support
- **Mock Client** — Deterministic mock for testing without API keys
- **Prompt Templates** — 13+ dev-focused templates (code review, debug, commit messages, security review, etc.)
- **Tool Registry** — Built-in tools for linting, complexity analysis, file reading, and git diff
- **Agents** — Tool-calling agent loop with a specialized `CoderAgent`
- **Chains** — Sequential and structured output chains with Pydantic models
- **RAG** — Text chunking, vector store, and retrieval-augmented generation
- **CLI** — `devai review`, `explain`, `debug`, `commit`, `tests`, `security`, `refactor`

## Installation

```bash
pip install -e .
# with dev dependencies
pip install -e ".[dev]"
```

## Quick Start

```python
from devai import LLMClient, MockLLMClient, DevAIConfig
from devai.core.models import Message, Role
from devai.prompts import CODE_REVIEW
from devai.agents import CoderAgent

# Use mock client for testing (no API key needed)
client = MockLLMClient(responses=["Looks good!"])
agent = CoderAgent(client=client)
result = agent.review("def add(a, b): return a + b")
print(result)

# Use real LLM (requires API key)
config = DevAIConfig.from_env()  # reads DEVAI_API_KEY or OPENAI_API_KEY
client = LLMClient(config)
messages = [
    Message(role=Role.SYSTEM, content=CODE_REVIEW.system),
    Message(role=Role.USER, content=CODE_REVIEW.render(
        language="python", code="def foo(): pass"
    )),
]
response = client.chat(messages)
print(response.content)
```

## CLI

```bash
export OPENAI_API_KEY=sk-...

devai review -f myfile.py
devai explain "def fib(n): ..."
devai debug "TypeError: ..." -f myfile.py
devai commit --staged
devai tests -f myfile.py --framework pytest
devai security -f myfile.py
devai refactor -f myfile.py --goal readability
```

## Configuration

Set environment variables (prefix `DEVAI_` or standard `OPENAI_API_KEY`):

| Variable | Default | Description |
|---|---|---|
| `DEVAI_API_KEY` | — | API key |
| `DEVAI_BASE_URL` | `https://api.openai.com/v1` | API base URL |
| `DEVAI_MODEL` | `gpt-4o-mini` | Chat model |
| `DEVAI_EMBEDDING_MODEL` | `text-embedding-3-small` | Embedding model |
| `DEVAI_TEMPERATURE` | `0.7` | Sampling temperature |
| `DEVAI_MAX_TOKENS` | `4096` | Max response tokens |

## Project Structure

```
src/devai/
├── core/       # LLM client, config, models, embeddings
├── prompts/    # Developer prompt templates
├── tools/      # Tool registry and code utilities
├── agents/     # Agent and CoderAgent
├── chains/     # Chain, SequentialChain, StructuredChain
├── memory/     # ConversationMemory
├── rag/        # RAG pipeline components
├── output/     # Structured output parsing
├── utils/      # Token estimation, code extraction
└── cli.py      # Command-line interface
```

## Testing

```bash
pip install -e ".[dev]"
python -m pytest
```

## License

MIT
