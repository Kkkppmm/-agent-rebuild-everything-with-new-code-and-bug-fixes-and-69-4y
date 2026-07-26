# DevAI

A Python AI library built for developers and programmers. DevAI provides LLM clients, prompt templates, tool-calling agents, RAG pipelines, and a CLI — everything you need to add AI capabilities to your dev workflows.

## Features

- **LLM Client** — OpenAI-compatible chat with streaming, JSON mode, tool calling, and async support
- **Mock Client** — Test without API keys using deterministic mock responses
- **Developer Prompts** — Pre-built templates for code review, debugging, commit messages, security review, and more
- **Agents** — Tool-calling agents with a specialized `CoderAgent` for programming tasks
- **Chains** — Simple, sequential, and structured (Pydantic) output chains
- **RAG** — Text chunking, vector store, and retrieval-augmented generation
- **CLI** — `devai review`, `explain`, `debug`, `commit`, `security`, `tests`

## Installation

```bash
pip install -e .
# with dev dependencies
pip install -e ".[dev]"
```

## Quick Start

### Basic chat

```python
from devai import LLMClient, DevAIConfig, Message

config = DevAIConfig(api_key="sk-...", model="gpt-4o-mini")
client = LLMClient(config)

response = client.chat([Message.user("Explain Python decorators")])
print(response.content)
```

### Mock mode (no API key)

```python
from devai import MockLLMClient, Message

client = MockLLMClient(responses=["Decorators wrap functions to extend behavior."])
response = client.chat([Message.user("Explain decorators")])
print(response.content)
```

### Code review with prompts

```python
from devai import MockLLMClient, Message
from devai.prompts import dev

code = "def add(a, b): return a + b"
prompt = dev.CODE_REVIEW.format(language="python", code=code)
client = MockLLMClient()
print(client.chat([Message.user(prompt)]).content)
```

### Coder agent with tools

```python
from devai import MockLLMClient
from devai.agents import CoderAgent

agent = CoderAgent(MockLLMClient())
result = agent.run("Analyze the complexity of: def foo(x): return x * 2")
print(result)
```

### RAG pipeline

```python
from devai import MockLLMClient
from devai.core.embedding import MockEmbeddingClient
from devai.rag import RAGChain

rag = RAGChain(MockLLMClient(), MockEmbeddingClient())
rag.add_text("DevAI is a Python library for developers.")
answer = rag.query("What is DevAI?")
print(answer)
```

### Structured output

```python
from pydantic import BaseModel
from devai import MockLLMClient
from devai.chains import StructuredChain

class Review(BaseModel):
    summary: str
    score: int

chain = StructuredChain(
    MockLLMClient(responses=['{"summary": "Looks good", "score": 8}']),
    Review,
)
result = chain.run("Review this code: pass")
print(result.summary, result.score)
```

## CLI

```bash
# Code review
devai review --file mymodule.py

# Explain code
echo "def fib(n): ..." | devai explain

# Generate commit message from diff
devai commit

# Security review
devai security --file app.py

# Generate tests
devai tests --file utils.py --framework pytest

# Use mock mode (no API key)
devai --mock review --code "x = 1"
```

## Configuration

Set environment variables or pass a `DevAIConfig`:

| Variable | Default | Description |
|----------|---------|-------------|
| `DEVAI_API_KEY` / `OPENAI_API_KEY` | — | API key |
| `DEVAI_BASE_URL` | `https://api.openai.com/v1` | API base URL |
| `DEVAI_MODEL` | `gpt-4o-mini` | Chat model |
| `DEVAI_TEMPERATURE` | `0.7` | Sampling temperature |

## Project Structure

```
src/devai/
├── core/       # LLM client, config, models, embeddings
├── prompts/    # PromptTemplate + developer prompts
├── tools/      # ToolRegistry + code utilities
├── agents/     # Agent, CoderAgent
├── chains/     # Chain, SequentialChain, StructuredChain
├── memory/     # ConversationMemory
├── rag/        # chunking, VectorStore, RAGChain
├── output/     # JSON/Pydantic parsers
├── utils/      # Token estimation, code block extraction
└── cli.py      # Command-line interface
```

## License

MIT
