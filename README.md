# DevAI

A lightweight Python AI library built for developers and programmers. DevAI gives you a clean, typed API for LLM chat, prompt templates, tool-calling agents, and code-focused utilities — without the heavyweight framework overhead.

## Features

- **Unified LLM client** — OpenAI-compatible API with sync, async, and streaming support
- **Prompt templates** — Reusable `{variable}` templates with built-in dev prompts (code review, debugging, test generation, and more)
- **Tool-calling agents** — Register Python functions as tools and run multi-step agent loops
- **Code utilities** — Static analysis helpers: explain code, lint Python, extract functions, search codebases
- **Chains** — Compose prompt + LLM pipelines for repeatable workflows
- **Conversation memory** — Rolling-window chat history with system prompts
- **Minimal dependencies** — Just `httpx` and `pydantic`

## Installation

```bash
pip install -e ".[dev]"
```

## Quick Start

```python
from devai import LLMClient, DevAIConfig

# Configure (or set DEVAI_API_KEY / OPENAI_API_KEY env vars)
client = LLMClient(DevAIConfig(api_key="sk-...", model="gpt-4o-mini"))

# Single-turn chat
answer = client.chat("What is a Python context manager?")
print(answer)
```

## Code Review

```python
from devai import LLMClient, Chain
from devai.prompts.dev import CODE_REVIEW

client = LLMClient()
chain = Chain(client, CODE_REVIEW)

result = chain.run(
    language="python",
    code='def divide(a, b):\n    return a / b  # bug!',
)
print(result["result"])
```

## Agents with Tools

```python
from devai import LLMClient, Agent, ToolRegistry
from devai.tools.code import explain_code

client = LLMClient()
tools = ToolRegistry()

@tools.register(description="Analyze Python code structure")
def analyze(code: str) -> str:
    return explain_code(code)

agent = Agent(client, tools=tools, system="You are a helpful code assistant.")
print(agent.run("What does this code do? def fib(n): return n if n < 2 else fib(n-1)+fib(n-2)"))
```

## Streaming

```python
from devai.core.models import Message, Role

for chunk in client.stream([Message(role=Role.USER, content="Hello!")]):
    print(chunk, end="")
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `DEVAI_API_KEY` | — | API key (falls back to `OPENAI_API_KEY`) |
| `DEVAI_BASE_URL` | `https://api.openai.com/v1` | API base URL |
| `DEVAI_MODEL` | `gpt-4o-mini` | Default model |
| `DEVAI_TEMPERATURE` | `0.7` | Sampling temperature |
| `DEVAI_MAX_TOKENS` | — | Max tokens per response |
| `DEVAI_TIMEOUT` | `60.0` | Request timeout (seconds) |

Works with any OpenAI-compatible endpoint (OpenAI, Azure, Ollama, vLLM, LiteLLM, etc.).

## Built-in Developer Prompts

```python
from devai.prompts import dev

dev.CODE_REVIEW      # Code review with actionable feedback
dev.EXPLAIN_CODE     # Plain-language code explanations
dev.GENERATE_TESTS   # Unit test generation
dev.REFACTOR         # Targeted refactoring
dev.DEBUG            # Error debugging assistance
dev.DOCSTRING        # Documentation generation
dev.COMMIT_MESSAGE   # Conventional commit messages
```

## Code Tools (no LLM required)

```python
from devai.tools.code import explain_code, lint_python, extract_functions, search_code

print(explain_code("def hello(): print('hi')"))
print(lint_python("def empty(): pass"))
print(extract_functions("def add(a, b): return a + b"))
```

## Project Structure

```
devai/
├── core/        # LLM client, config, models
├── prompts/     # Templates and dev prompts
├── tools/       # Tool registry and code utilities
├── agents/      # Tool-calling agent loop
├── chains/      # Prompt + LLM pipelines
├── memory/      # Conversation history
└── utils/       # Retry helpers
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check devai tests
```

## License

MIT
