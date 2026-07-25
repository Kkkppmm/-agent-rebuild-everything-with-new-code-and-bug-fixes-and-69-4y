# DevAI

A Python AI library built for developers and programmers. DevAI provides a clean, modular toolkit for building LLM-powered applications — from simple prompt chains to autonomous coding agents with tool use.

## Features

- **OpenAI-compatible LLM client** — sync, async, and streaming chat completions
- **Developer prompt templates** — code review, debugging, commit messages, API design, and more
- **Tool registry** — register Python functions as LLM tools with automatic schema generation
- **Built-in dev tools** — read files, search code, git diff, lint Python, measure complexity
- **Agents** — ReAct-style tool-calling loop with `Agent` and `CoderAgent`
- **Chains** — compose prompt templates with LLM calls into reusable pipelines
- **Sequential chains** — multi-step pipelines that pass outputs between steps
- **JSON mode** — structured JSON responses via `chat_json()`
- **Automatic retries** — exponential backoff on rate limits and server errors
- **Conversation memory** — multi-turn history with message and token limits
- **Utilities** — token estimation, code block extraction, text truncation

## Installation

```bash
pip install -e .
# with dev dependencies
pip install -e ".[dev]"
```

## Quick Start

### Chat with an LLM

```python
from devai import LLMClient, DevAIConfig, Message

config = DevAIConfig(
    api_key="sk-...",
    model="gpt-4o-mini",
)
client = LLMClient(config)

response = client.chat([
    Message.system("You are a helpful coding assistant."),
    Message.user("Explain Python decorators in 2 sentences."),
])
print(response.content)
```

### Use Developer Prompts

```python
from devai.prompts.dev_prompts import CODE_REVIEW, DEBUG
from devai import Chain

chain = Chain(CODE_REVIEW)
review = chain.run(
    language="python",
    code="def add(a, b): return a + b",
)
print(review)
```

### Build an Agent with Tools

```python
from devai import Agent, ToolRegistry

tools = ToolRegistry()

@tools.register(description="Get the current project version")
def get_version() -> str:
    return "1.0.0"

agent = Agent(tools=tools)
result = agent.run("What version is this project?")
print(result.content)
```

### Use the Coder Agent

```python
from devai import CoderAgent

agent = CoderAgent(project_root=".")
result = agent.run("Find all TODO comments in Python files")
print(result.content)
```

### Stream Responses

```python
from devai import LLMClient, Message

client = LLMClient()
for token in client.stream([Message.user("Write a fibonacci function in Python")]):
    print(token, end="", flush=True)
```

### Structured JSON Output

```python
from devai import LLMClient, Message

client = LLMClient()
data = client.chat_json([
    Message.system("Respond with valid JSON only."),
    Message.user("List 3 Python web frameworks with a one-line description each."),
])
print(data)
```

### Multi-Step Pipelines

```python
from devai import SequentialChain
from devai.prompts.dev_prompts import CODE_REVIEW, REFACTOR

pipeline = SequentialChain([
    (CODE_REVIEW, "review"),
    (REFACTOR.partial(goal="readability"), "refactored"),
])
result = pipeline.run(language="python", code="def f(x): return x*2")
print(result["review"])
print(result["refactored"])
```

## Configuration

DevAI reads configuration from environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DEVAI_API_KEY` | — | API key (falls back to `OPENAI_API_KEY`) |
| `DEVAI_BASE_URL` | `https://api.openai.com/v1` | API base URL |
| `DEVAI_MODEL` | `gpt-4o-mini` | Default model |
| `DEVAI_TEMPERATURE` | `0.7` | Sampling temperature |
| `DEVAI_MAX_TOKENS` | `4096` | Max completion tokens |

Works with any OpenAI-compatible API (OpenAI, Azure, Ollama, vLLM, LiteLLM, etc.).

## Package Structure

```
src/devai/
├── core/       # LLM client, config, models, exceptions
├── prompts/    # PromptTemplate + dev workflow prompts
├── tools/      # ToolRegistry + built-in dev tools
├── agents/     # Agent and CoderAgent
├── chains/     # Prompt + LLM pipelines
├── memory/     # ConversationMemory
└── utils/      # Token and code utilities
```

## Built-in Developer Tools

| Tool | Description |
|------|-------------|
| `read_file` | Read a file from the project |
| `list_directory` | List directory contents |
| `search_code` | Regex search across code files |
| `git_diff` | Get git diff output |
| `explain_code` | Static analysis of Python code |
| `lint_python` | Basic Python lint checks |
| `count_complexity` | Cyclomatic complexity per function |

## Development

```bash
pip install -e ".[dev]"
python -m pytest
python -m pytest --cov=devai
```

## License

MIT
