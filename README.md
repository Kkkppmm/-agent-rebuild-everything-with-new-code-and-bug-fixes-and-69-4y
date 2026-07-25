# DevAI

A lightweight Python AI library built for developers and programmers. DevAI provides an OpenAI-compatible LLM client, prompt templates, tool-calling agents, composable chains, and conversation memory — everything you need to build AI-powered dev tools.

## Features

- **LLM Client** — Sync/async chat completions, streaming, embeddings, and structured JSON output
- **Prompt Templates** — Built-in templates for code review, debugging, refactoring, test generation, docs, and commit messages
- **Tool Registry** — Register Python functions as LLM tools with auto-generated JSON schemas
- **Agents** — Autonomous tool-calling loop with configurable max rounds
- **CoderAgent** — Pre-configured agent with code analysis tools (AST explain, lint, search, git diff)
- **Chains** — Simple prompt → LLM pipelines with composition support
- **Memory** — Sliding-window conversation history for multi-turn interactions
- **Code Tools** — AST-based code explanation, Python linting, complexity analysis, and regex search
- **Utilities** — Token estimation and markdown code block extraction

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

config = DevAIConfig(api_key="sk-...", model="gpt-4o-mini")
client = LLMClient(config)

response = client.chat([
    Message.system("You are a helpful coding assistant."),
    Message.user("What is a Python decorator?"),
])
print(response.content)
```

### Use a Prompt Template

```python
from devai import Chain
from devai.prompts import CODE_REVIEW

chain = Chain(prompt=CODE_REVIEW)
review = chain.run(language="python", code="def add(a, b): return a + b")
print(review)
```

### Build an Agent with Tools

```python
from devai import Agent, ToolRegistry
from devai.tools import explain_code, lint_python

registry = ToolRegistry()
registry.register(explain_code)
registry.register(lint_python)

agent = Agent(tools=registry)
answer = agent.run("Explain and lint this code: def foo(): pass")
print(answer)
```

### Use the CoderAgent

```python
from devai import CoderAgent

coder = CoderAgent(working_directory="/path/to/project")
answer = coder.run("Review the changes in my git diff and suggest improvements")
print(answer)
```

### Structured Output

```python
from pydantic import BaseModel
from devai import LLMClient, Message

class CodeReview(BaseModel):
    score: int
    issues: list[str]
    summary: str

client = LLMClient()
review = client.chat_structured(
    [Message.user("Review: def add(a,b): return a+b")],
    CodeReview,
)
print(review.score, review.summary)
```

### Stream Responses

```python
from devai import LLMClient, Message

client = LLMClient()
for chunk in client.stream([Message.user("Write a hello world in Rust")]):
    print(chunk, end="", flush=True)
```

### Generate Embeddings

```python
from devai import LLMClient

client = LLMClient()
vectors = client.embed(["def hello(): pass", "class Foo: pass"])
print(len(vectors), len(vectors[0]))
```

## Configuration

Set environment variables or pass a `DevAIConfig`:

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` / `DEVAI_API_KEY` | — | API key |
| `DEVAI_BASE_URL` | `https://api.openai.com/v1` | API base URL |
| `DEVAI_MODEL` | `gpt-4o-mini` | Model name |
| `DEVAI_EMBEDDING_MODEL` | `text-embedding-3-small` | Embedding model |
| `DEVAI_TEMPERATURE` | `0.7` | Sampling temperature |
| `DEVAI_MAX_RETRIES` | `3` | Retry count for transient failures |

```python
from devai import DevAIConfig

config = DevAIConfig.from_env()  # reads DEVAI_* vars
```

## Built-in Prompt Templates

| Template | Variables | Use Case |
|----------|-----------|----------|
| `CODE_REVIEW` | `language`, `code` | Review code for bugs and style |
| `DEBUG_ERROR` | `error`, `code` | Diagnose runtime errors |
| `EXPLAIN_CODE` | `language`, `code` | Explain how code works |
| `GENERATE_TESTS` | `language`, `framework`, `code` | Generate unit tests |
| `REFACTOR` | `language`, `goals`, `code` | Refactor with goals |
| `WRITE_DOCS` | `language`, `format`, `code` | Write documentation |
| `COMMIT_MESSAGE` | `diff` | Generate conventional commit messages |
| `API_DESIGN` | `description`, `language` | Design REST APIs |

## Project Structure

```
devai/
├── core/       # LLMClient, DevAIConfig, Message/Tool models, exceptions
├── prompts/    # PromptTemplate + developer prompt library
├── tools/      # ToolRegistry + code utilities
├── agents/     # Agent, CoderAgent with tool-calling loop
├── chains/     # Prompt → LLM pipelines
├── memory/     # ConversationMemory
└── utils/      # Token estimation, code block extraction
```

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```

## License

MIT
