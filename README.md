# DevAI

A Python AI library built for developers and programmers. DevAI provides LLM clients, developer-focused prompts, tool-calling agents, chains, RAG, and a CLI for everyday coding tasks.

## Features

- **Provider-agnostic LLM client** — OpenAI, Anthropic, Ollama (local), and a mock client for testing
- **Developer prompts** — Code review, debugging, commit messages, security review, refactoring, and more
- **Tool registry** — Register and invoke tools in agent loops
- **Agents** — `CoderAgent` with automatic tool-calling
- **Chains** — Sequential and structured output chains
- **RAG** — Text chunking, vector store, and retrieval-augmented generation
- **CLI** — `devai review`, `explain`, `debug`, `commit`, `pr`, `changelog`, `agent`, and more
- **Async API** — `acomplete` and `astream` for async workflows
- **Batch processing** — `BatchRunner` for concurrent LLM requests
- **Response caching** — `CachedLLMClient` to avoid duplicate API calls

## Installation

```bash
pip install -e .
# With dev dependencies
pip install -e ".[dev]"
# With provider SDKs
pip install -e ".[all]"
```

## Quick Start

```python
from devai import LLMClient, DevAIConfig
from devai.prompts import PromptTemplate, CODE_REVIEW

config = DevAIConfig(api_key="your-key", provider="openai", model="gpt-4o-mini")
client = LLMClient(config)

prompt = PromptTemplate(CODE_REVIEW)
response = client.complete(prompt.format(code="def foo(): pass"))
print(response.content)
```

### CodeAssistant (simple API)

```python
from devai import CodeAssistant

assistant = CodeAssistant.mock()
print(assistant.review("def foo(): pass"))
print(assistant.explain("x = [i**2 for i in range(10)]"))
print(assistant.full_review("def bar(): pass"))
```

### Mock client (no API key needed)

```python
from devai.core.client import MockLLMClient

client = MockLLMClient(responses=["This code looks fine."])
print(client.complete("review this").content)
```

### Async usage

```python
import asyncio
from devai.core.client import MockLLMClient
from devai.core.streaming import collect_stream_async

async def main():
    client = MockLLMClient(responses=["Async review complete."])
    response = await client.acomplete("review this code")
    print(response.content)

    text = await collect_stream_async(client.astream("explain this"))
    print(text)

asyncio.run(main())
```

### Agent with tools

```python
from devai.agents import CoderAgent
from devai.core.client import MockLLMClient
from devai.tools import ToolRegistry, explain_code

registry = ToolRegistry()
registry.register(explain_code)
agent = CoderAgent(client=MockLLMClient(), tools=registry)
result = agent.run("Explain what this function does")
```

### Pipeline

```python
from devai.core.client import MockLLMClient
from devai.pipeline import DevPipeline

client = MockLLMClient(responses=["Review passed.", "No security issues."])
pipeline = DevPipeline(client=client)
pipeline.review("def foo(): pass")
print(pipeline.summary())
```

### Batch processing

```python
from devai import BatchRunner, MockLLMClient

client = MockLLMClient(responses=["Review 1", "Review 2"])
runner = BatchRunner(client)
results = runner.run_prompts(["review file a", "review file b"])
```

### Response caching

```python
from devai import CachedLLMClient, MockLLMClient

client = CachedLLMClient(MockLLMClient(responses=["Cached response"]))
print(client.complete("same prompt").content)
print(client.complete("same prompt").content)  # served from cache
print(client.stats)
```

### CLI

```bash
devai review --file mycode.py
devai explain --code "def add(a, b): return a + b"
devai commit --diff "$(git diff)"
devai pr --staged
devai changelog --changes "$(git log --oneline -5)"
devai agent --task "Find bugs in src/"
```

See `examples/` for more usage patterns.

## Configuration

Set environment variables or pass a `DevAIConfig`:

| Variable | Description |
|----------|-------------|
| `DEVAI_API_KEY` | API key for the provider |
| `DEVAI_PROVIDER` | `openai`, `anthropic`, `ollama`, or `mock` |
| `DEVAI_MODEL` | Model name (e.g. `gpt-4o-mini`) |
| `DEVAI_BASE_URL` | Custom API base URL |

### Local models with Ollama

```python
from devai import LLMClient, DevAIConfig

config = DevAIConfig(provider="ollama", model="llama3.2")
client = LLMClient(config)
print(client.complete("Explain Python generators").content)
```

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```

## License

MIT
