# DevAI

A Python AI library built for developers and programmers. DevAI provides a clean, composable toolkit for building AI-powered developer workflows — code review, debugging, refactoring, agents with tool calling, RAG over codebases, and more.

## Features

- **LLM Client** — OpenAI-compatible API with streaming, async, JSON mode, and retries
- **Mock Client** — Test without API keys
- **Code Assistant** — High-level facade for review, explain, debug, refactor, security audit, test generation
- **Prompt Templates** — Ready-made prompts for common developer tasks
- **Tool Registry** — Extensible tool system with built-in code utilities
- **Agents** — Tool-calling agent loop for autonomous coding tasks
- **Chains** — Composable prompt chains with structured output
- **RAG** — Chunk, embed, and retrieve over documents and code
- **CLI** — Command-line interface for quick tasks
- **Pipeline** — Multi-step review/debug/test workflows

## Installation

```bash
pip install devai

# With OpenAI support
pip install "devai[openai]"

# Development
pip install -e ".[dev]"
```

## Quick Start

```python
from devai import CodeAssistant, DevAIConfig

# Use mock client for testing (no API key needed)
config = DevAIConfig.mock()
assistant = CodeAssistant(config=config)

# Review code
result = assistant.review("""
def add(a, b):
    return a + b
""")
print(result)

# Explain code
explanation = assistant.explain("async def fetch(url): ...")

# Debug an error
fix = assistant.debug(
    code="x = 1 / 0",
    error="ZeroDivisionError: division by zero",
)
```

## With a Real LLM

```python
from devai import CodeAssistant, DevAIConfig

config = DevAIConfig(
    api_key="sk-...",
    model="gpt-4o-mini",
    base_url="https://api.openai.com/v1",
)
assistant = CodeAssistant(config=config)
print(assistant.review(open("main.py").read()))
```

## Agents

```python
from devai import DevAIConfig
from devai.agents import CoderAgent
from devai.tools import ToolRegistry, default_tools

config = DevAIConfig.mock()
registry = ToolRegistry()
for tool in default_tools():
    registry.register(tool)

agent = CoderAgent(config=config, tools=registry)
result = agent.run("Find all TODO comments in the current directory")
print(result)
```

## RAG

```python
from devai import DevAIConfig
from devai.rag import RAGChain, VectorStore, chunk_text

config = DevAIConfig.mock()
docs = chunk_text(open("README.md").read())
store = VectorStore()
store.add_documents(docs)

rag = RAGChain(config=config, store=store)
answer = rag.query("How do I install DevAI?")
print(answer)
```

## CLI

```bash
devai review main.py
devai explain "def fib(n): ..."
devai debug --code app.py --error "ImportError: No module named foo"
devai commit --diff git_diff.txt
devai security auth.py
devai agent "list all Python files"
```

## License

MIT
