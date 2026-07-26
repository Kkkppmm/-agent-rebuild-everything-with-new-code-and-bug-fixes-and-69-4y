# DevAI

A Python AI library built for developers and programmers. DevAI provides LLM clients, prompt templates, tool-calling agents, RAG pipelines, and a CLI for common coding tasks.

## Features

- **LLM Client** — OpenAI-compatible client with retries, streaming, and JSON mode
- **Mock Client** — Test without API keys
- **Prompt Templates** — Built-in prompts for code review, debugging, commit messages, security review, and more
- **Tool Registry** — Register and execute functions as agent tools
- **Agents** — Base agent and `CoderAgent` with developer tools
- **Chains** — Composable single-step, sequential, and structured output chains
- **RAG** — Text chunking, vector store, and retrieval-augmented generation
- **CLI** — `devai review`, `explain`, `debug`, `commit`, `tests`, `security`

## Installation

```bash
pip install -e ".[dev]"
```

## Quick Start

```python
from devai import MockLLMClient, CoderAgent, PromptTemplate
from devai.prompts import dev_prompts

# Use mock client for testing (no API key needed)
llm = MockLLMClient(responses=["This code looks good!"])
agent = CoderAgent(llm)
result = agent.review("def add(a, b): return a + b")
print(result)

# Format a prompt template
prompt = dev_prompts.CODE_REVIEW.format(
    language="python",
    code="def foo(): pass",
    extra_instructions="Focus on security.",
)
print(prompt)
```

## Real API Usage

```python
from devai import LLMClient, DevAIConfig

config = DevAIConfig.from_env()  # reads OPENAI_API_KEY
client = LLMClient(config)
answer = client.complete("Explain Python decorators in one paragraph.")
print(answer)
```

## RAG Example

```python
from devai import MockLLMClient, VectorStore
from devai.rag import RAGChain

llm = MockLLMClient(responses=["Based on the docs, use pip install."])
store = VectorStore()
chain = RAGChain(llm, store)
chain.ingest("DevAI is installed with pip install -e .")
answer = chain.run("How do I install DevAI?")
```

## CLI

```bash
# Review code (uses mock by default with --mock)
devai --mock review --code "def add(a,b): return a+b"

# Generate commit message from git diff
devai --mock commit

# Security review
devai --mock security --file myapp.py
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | API key for LLM provider | — |
| `DEVAI_BASE_URL` | API base URL | `https://api.openai.com/v1` |
| `DEVAI_MODEL` | Chat model | `gpt-4o-mini` |
| `DEVAI_EMBEDDING_MODEL` | Embedding model | `text-embedding-3-small` |

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```

## License

MIT
