# DevAI

A Python AI library built for developers and programmers. DevAI provides an OpenAI-compatible LLM client, pre-built developer prompts, tool-calling agents, and code utilities — everything you need to build AI-powered dev tools.

## Features

- **LLM Client** — OpenAI-compatible async client with retries, JSON mode, and tool calling
- **Developer Prompts** — Ready-made templates for code review, debugging, commit messages, API design, and more
- **Tool Registry** — Register Python functions as LLM tools with automatic schema inference
- **Agents** — Tool-calling agent loop with `CoderAgent` pre-loaded with code utilities
- **Chains** — Compose prompt → LLM pipelines, including sequential multi-step chains
- **Memory** — Conversation history with token-based truncation
- **Code Utils** — Built-in tools: `read_file`, `search_code`, `git_diff`, `lint_python`, `count_complexity`

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
from devai import Chain
from devai.prompts import CODE_REVIEW

chain = Chain(CODE_REVIEW, config=DevAIConfig(api_key="sk-..."))
result = chain.run_sync(code="def add(a, b): return a + b", language="python")
print(result)
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

### Developer prompts

```python
from devai.prompts import DEBUG, COMMIT_MESSAGE, API_DESIGN, WRITE_TESTS

prompt = DEBUG.format(
    language="python",
    error="TypeError: unsupported operand type(s)",
    code="result = '5' + 5",
    context="User input validation",
)
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
├── chains/     # Chain, SequentialChain
├── memory/     # ConversationMemory
└── utils/      # Token estimation, code block extraction
```

## Testing

```bash
pip install -e ".[dev]"
python -m pytest
```

## License

MIT
