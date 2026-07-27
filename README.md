# DevAI

A Python AI library built for developers and programmers. DevAI provides LLM clients, prompt templates, tool-calling agents, chains, RAG, and a CLI for common dev workflows.

## Features

- **LLM Clients** — OpenAI-compatible API client with streaming, JSON mode, retries, and a mock client for testing
- **Prompt Templates** — Ready-made prompts for code review, debugging, commit messages, security review, and more
- **Tool Registry** — Built-in tools for code analysis, file reading, git diff, and complexity counting
- **Agents** — Tool-calling agent loop with a specialized `CoderAgent`
- **Chains** — Sequential and structured output chains with Pydantic models
- **RAG** — Text chunking, vector store, and retrieval-augmented generation
- **CLI** — Command-line interface for review, explain, debug, commit, tests, security, and refactor

## Installation

```bash
pip install -e .
# with dev dependencies
pip install -e ".[dev]"
```

## Quick Start

```python
from devai import DevAIConfig, LLMClient, PromptTemplate, CODE_REVIEW

config = DevAIConfig(api_key="sk-...", model="gpt-4o-mini")
client = LLMClient(config)

prompt = PromptTemplate(CODE_REVIEW).format(code="def foo(): pass")
response = client.chat([{"role": "user", "content": prompt}])
print(response.content)
```

### Mock Client (no API key needed)

```python
from devai import MockLLMClient

client = MockLLMClient(responses=["Looks good! No issues found."])
response = client.chat([{"role": "user", "content": "Review this code"}])
```

### Agent with Tools

```python
from devai import Agent, LLMClient, DevAIConfig, ToolRegistry

registry = ToolRegistry()
registry.register_builtins()

agent = Agent(
    client=LLMClient(DevAIConfig(api_key="sk-...")),
    tools=registry,
    system_prompt="You are a helpful coding assistant.",
)
result = agent.run("Explain the complexity of this project")
```

### CLI

```bash
devai review path/to/file.py
devai explain "def fib(n): ..."
devai debug --error "NameError: name 'x' is not defined"
devai commit --diff "$(git diff --staged)"
devai security path/to/file.py
```

## Configuration

Set environment variables or pass a `DevAIConfig`:

| Variable | Description | Default |
|----------|-------------|---------|
| `DEVAI_API_KEY` | API key for the LLM provider | — |
| `DEVAI_BASE_URL` | API base URL | `https://api.openai.com/v1` |
| `DEVAI_MODEL` | Model name | `gpt-4o-mini` |
| `DEVAI_MAX_TOKENS` | Max response tokens | `4096` |
| `DEVAI_TEMPERATURE` | Sampling temperature | `0.2` |

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```

## License

MIT
