# DevAI

A Python AI library built for developers and programmers. DevAI provides a clean, composable toolkit for building AI-powered developer workflows — from code review and debugging to agents, RAG, and structured output.

## Features

- **LLM Client** — OpenAI-compatible client with streaming, tool calling, JSON mode, and async support
- **Mock Client** — Test without API keys using `MockLLMClient`
- **Developer Prompts** — 13+ pre-built templates (code review, debug, commit messages, security review, etc.)
- **Agents** — Tool-calling agents with `CoderAgent` for programming tasks
- **Chains** — Simple, sequential, and structured (Pydantic) chains
- **RAG** — Text chunking, vector store, and retrieval-augmented generation
- **Pipeline** — Composable workflows for review, debug, test generation, and more
- **CLI** — Command-line interface for all common tasks
- **Tools** — Built-in code utilities (lint, complexity, file read, git diff)

## Installation

```bash
pip install -e .
# or with dev dependencies
pip install -e ".[dev]"
```

## Quick Start

```python
from devai import MockLLMClient, SimpleChain
from devai.prompts import CODE_REVIEW

client = MockLLMClient()
chain = SimpleChain(client=client, prompt=CODE_REVIEW)
result = chain.run(language="python", code="def hello(): print('hi')")
print(result)
```

## Configuration

Set environment variables or pass a config object:

```python
from devai import DevAIConfig, LLMClient

config = DevAIConfig(
    api_key="sk-...",
    model="gpt-4o-mini",
    temperature=0.7,
)
client = LLMClient(config)
```

Environment variables:
- `OPENAI_API_KEY` or `DEVAI_API_KEY` — API key
- `DEVAI_MODEL` — Model name (default: `gpt-4o-mini`)
- `DEVAI_BASE_URL` — API base URL

## Agents

```python
from devai import MockLLMClient
from devai.agents import CoderAgent

agent = CoderAgent(client=MockLLMClient())
result = agent.review("def add(a, b): return a + b")
```

## Pipeline

```python
from devai import MockLLMClient
from devai.pipeline import DevPipeline, PipelineStep

pipeline = DevPipeline(client=MockLLMClient())
results = pipeline.run_all(code, steps=[PipelineStep.REVIEW, PipelineStep.SECURITY])
```

## CLI

```bash
# Code review
devai review --file mycode.py --mock

# Debug an error
devai debug --file app.py --error "ZeroDivisionError" --mock

# Generate commit message from diff
git diff | devai commit --mock

# Run coding agent
devai agent --task "Explain this codebase" --mock
```

## RAG

```python
from devai import LLMClient, EmbeddingClient
from devai.rag import RAGChain

rag = RAGChain(client=LLMClient(), embedding_client=EmbeddingClient())
rag.ingest("Your documentation text here...")
answer = rag.query("How do I configure the API?")
```

## Structured Output

```python
from pydantic import BaseModel
from devai.chains import StructuredChain

class CodeReview(BaseModel):
    summary: str
    issues: list[str]
    score: int

chain = StructuredChain(
    client=MockLLMClient(responses=['{"summary": "ok", "issues": [], "score": 8}']),
    output_model=CodeReview,
    prompt_template="Review this code: {code}",
)
result = chain.run(code="def f(): pass")
```

## Testing

```bash
pip install -e ".[dev]"
python -m pytest
```

## License

MIT
