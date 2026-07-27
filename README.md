# DevAI

A lightweight Python AI library built for developers and programmers. DevAI wraps LLM APIs with developer-focused workflows: code review, debugging, refactoring, agents with tools, RAG, and composable chains.

## Features

- **LLM Client** — OpenAI-compatible API with sync/async, streaming, retries, and JSON mode
- **Code Assistant** — High-level facade for review, explain, debug, refactor, security audit, and test generation
- **Agents** — Tool-calling agents for autonomous coding tasks
- **Chains** — Sequential and structured output pipelines
- **RAG** — Chunk, embed, and retrieve context for grounded answers
- **CLI** — `devai review`, `explain`, `debug`, `commit`, and more
- **Mock Client** — Test without API keys

## Installation

```bash
pip install -e .
# or with dev dependencies
pip install -e ".[dev]"
```

## Quick Start

```python
from devai import CodeAssistant, DevAIConfig, MockLLMClient

# Use mock client for testing (no API key needed)
client = MockLLMClient()
assistant = CodeAssistant(client=client)

code = '''
def divide(a, b):
    return a / b
'''

review = assistant.review(code)
print(review)

explanation = assistant.explain(code)
print(explanation)
```

## With a Real LLM

```python
from devai import CodeAssistant, DevAIConfig, LLMClient

config = DevAIConfig(
    api_key="sk-...",
    base_url="https://api.openai.com/v1",
    model="gpt-4o-mini",
)
client = LLMClient(config)
assistant = CodeAssistant(client=client)

result = assistant.debug(code, error="ZeroDivisionError: division by zero")
```

## Agents

```python
from devai import Agent, CoderAgent, ToolRegistry, MockLLMClient
from devai.tools import read_file, search_code

registry = ToolRegistry()
registry.register(read_file)
registry.register(search_code)

agent = CoderAgent(client=MockLLMClient(), tools=registry)
response = agent.run("Find and explain the main entry point")
```

## RAG

```python
from devai import MockLLMClient
from devai.rag import VectorStore, RAGChain, chunk_text

docs = chunk_text(open("README.md").read())
store = VectorStore()
store.add_documents(docs)

chain = RAGChain(client=MockLLMClient(), store=store)
answer = chain.query("How do I install DevAI?")
```

## CLI

```bash
export OPENAI_API_KEY=sk-...
devai review path/to/file.py
devai explain path/to/file.py
devai debug path/to/file.py --error "TypeError: ..."
devai commit --staged
devai agent "refactor the auth module"
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | API key for LLM provider |
| `DEVAI_BASE_URL` | API base URL (default: OpenAI) |
| `DEVAI_MODEL` | Model name (default: `gpt-4o-mini`) |

## Development

```bash
pip install -e ".[dev]"
python -m pytest
ruff check src tests
```

## License

MIT
