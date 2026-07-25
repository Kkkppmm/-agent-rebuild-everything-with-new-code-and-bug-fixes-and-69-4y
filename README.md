# DevAI

A Python AI library built for developers and programmers. DevAI provides an OpenAI-compatible LLM client, pre-built developer prompts, tool-calling agents, and code utilities — everything you need to build AI-powered dev tools.

## Features

- **LLM Client** — OpenAI-compatible async client with retries, JSON mode, streaming, and tool calling
- **Developer Prompts** — Ready-made templates for code review, debugging, commit messages, API design, security audits, and more
- **Tool Registry** — Register Python functions as LLM tools with automatic schema inference
- **Agents** — Tool-calling agent loop with `CoderAgent` pre-loaded with code utilities
- **Chains** — Compose prompt → LLM pipelines, including sequential multi-step and structured Pydantic output chains
- **Memory** — Conversation history with token-based truncation
- **RAG** — In-memory vector store, text chunking, and retrieval-augmented generation chains
- **Mock clients** — Test chains and agents without API keys using `MockLLMClient` and `MockEmbeddingClient`
- **Embeddings** — OpenAI-compatible embedding client for semantic search
- **Code Utils** — Built-in tools: `read_file`, `search_code`, `git_diff`, `lint_python`, `count_complexity`
- **CLI** — Command-line tools for quick code review, debugging, test generation, and more

## Installation

```bash
pip install -e .
# with dev dependencies
pip install -e ".[dev]"
```

Set your API key:

```bash
export OPENAI_API_KEY=sk-...
# or
export DEVAI_API_KEY=sk-...
```

## Quick Start

### Simple prompt chain

```python
from devai import Chain, DevAIConfig
from devai.prompts import CODE_REVIEW

chain = Chain(CODE_REVIEW, config=DevAIConfig(api_key="sk-..."))
result = chain.run_sync(code="def add(a, b): return a + b", language="python")
print(result)
```

### Streaming responses

```python
from devai import Chain, DevAIConfig
from devai.prompts import EXPLAIN_CODE

chain = Chain(EXPLAIN_CODE, config=DevAIConfig(api_key="sk-..."))
async for token in chain.stream(code="...", language="python", audience="beginner"):
    print(token, end="", flush=True)
```

### Structured output with Pydantic

```python
from pydantic import BaseModel
from devai import StructuredChain, DevAIConfig

class ReviewResult(BaseModel):
    summary: str
    severity: str

chain = StructuredChain(
    "Review this code: {code}",
    output_model=ReviewResult,
    config=DevAIConfig(api_key="sk-...", json_mode=True),
)
result = chain.run_sync(code="def foo(): pass")
print(result.summary)
```

### Coder agent with tools

```python
from devai import CoderAgent, DevAIConfig

agent = CoderAgent(config=DevAIConfig(api_key="sk-..."))
answer = agent.run_sync("Read the file main.py and suggest improvements")
print(answer)
```

### Custom tools

```python
from devai import Agent, ToolRegistry, DevAIConfig

registry = ToolRegistry()

@registry.register(description="Get the current weather for a city")
def get_weather(city: str) -> str:
    return f"Sunny in {city}"

agent = Agent(config=DevAIConfig(api_key="sk-..."), tools=registry)
result = agent.run_sync("What's the weather in Tokyo?")
```

### RAG over docs or code

```python
from devai import RAGChain, MockLLMClient, DevAIConfig

mock = MockLLMClient(responses=["Use connection pooling for better throughput."])
rag = RAGChain(client=mock, config=DevAIConfig(api_key="test"))

rag.ingest_sync([
    "PostgreSQL connection pooling reduces latency.",
    "Index foreign keys for faster joins.",
])
answer = rag.run_sync("How do I speed up database access?")
```

### Testing without API calls

```python
from devai import Chain, MockLLMClient, DevAIConfig
from devai.prompts import CODE_REVIEW

mock = MockLLMClient(responses=["No issues found."])
chain = Chain(CODE_REVIEW, client=mock, config=DevAIConfig(api_key="test"))
assert "issues" in chain.run_sync(code="x = 1", language="python").lower()
```

### Developer prompts

```python
from devai.prompts import DEBUG, COMMIT_MESSAGE, API_DESIGN, WRITE_TESTS, SECURITY_REVIEW

prompt = DEBUG.format(
    language="python",
    error="TypeError: unsupported operand type(s)",
    code="result = '5' + 5",
    context="User input validation",
)
```

### CLI

```bash
devai review main.py
devai explain app.py --audience beginner
devai debug --error "TypeError" --file main.py
devai commit --staged
devai tests utils.py --framework pytest
devai security auth.py
```

## Configuration

```python
from devai import DevAIConfig

# Explicit config
config = DevAIConfig(
    api_key="sk-...",
    base_url="https://api.openai.com/v1",  # any OpenAI-compatible endpoint
    model="gpt-4o-mini",
    temperature=0.7,
    max_retries=3,
    json_mode=False,
)

# From environment (DEVAI_API_KEY, DEVAI_MODEL, etc.)
config = DevAIConfig.from_env()
```

## Project Structure

```
src/devai/
├── core/       # LLMClient, DevAIConfig, models, exceptions
├── prompts/    # PromptTemplate + dev prompt library
├── tools/      # ToolRegistry + code utilities
├── agents/     # Agent, CoderAgent
├── chains/     # Chain, SequentialChain, StructuredChain
├── memory/     # ConversationMemory
├── rag/        # VectorStore, chunking, RAGChain
├── output/     # Structured output parsers
├── utils/      # Token estimation, code block extraction
└── cli.py      # Command-line interface
```

## Testing

```bash
pip install -e ".[dev]"
python -m pytest
```

## License

MIT
