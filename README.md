# DevAI

A Python AI library built for developers and programmers. DevAI provides LLM clients, developer-focused prompt templates, tool-calling agents, chains, RAG, and a CLI for everyday coding tasks.

## Features

- **LLM Client** — OpenAI-compatible API client with streaming, retries, JSON mode, and tool calling
- **Mock Client** — Test without API keys
- **Prompt Templates** — Pre-built prompts for code review, debugging, commits, security, refactoring, and more
- **Agents** — Tool-calling agents with a pre-built `CoderAgent`
- **Chains** — Single-step, sequential, and structured (Pydantic) chains
- **RAG** — Chunking, vector store, and retrieval-augmented generation
- **Memory** — Token-aware conversation memory
- **CLI** — `devai review`, `explain`, `debug`, `commit`, `tests`, `security`, `refactor`

## Installation

```bash
pip install -e .
pip install -e ".[dev]"  # with test dependencies
```

## Quick Start

```python
from devai import MockLLMClient, Chain, PromptTemplate
from devai.prompts import CODE_REVIEW

client = MockLLMClient(responses=["Looks good! Consider adding type hints."])
chain = Chain(client, CODE_REVIEW)

result = chain.run(
    code="def hello(): print('hi')",
    language="python",
    context="Entry point",
)
print(result)
```

### With a real LLM

```python
import os
from devai import LLMClient, DevAIConfig, CoderAgent

config = DevAIConfig(api_key=os.environ["OPENAI_API_KEY"])
agent = CoderAgent(LLMClient(config))
answer = agent.run("Review the main.py file for bugs")
```

### RAG

```python
from devai import MockLLMClient, RAGChain

client = MockLLMClient(responses=["Based on the docs, use async/await."])
rag = RAGChain(client)
rag.index(["Python asyncio runs coroutines on a single thread."])
print(rag.query("How does asyncio work?"))
```

### Structured output

```python
from pydantic import BaseModel
from devai.chains import StructuredChain
from devai import MockLLMClient

class Review(BaseModel):
    score: int
    summary: str

client = MockLLMClient(responses=['{"score": 8, "summary": "Clean code"}'])
chain = StructuredChain(client, Review, "Review this code: {code}")
result = chain.run(code="def f(): pass")
print(result.score, result.summary)
```

## CLI

```bash
# Review code (use --mock without API key)
devai --mock review -f myfile.py

devai explain -f myfile.py
devai debug -f myfile.py -e "TypeError: unsupported operand"
devai commit --staged
devai tests -f myfile.py
devai security -f myfile.py
devai refactor -f myfile.py -g "reduce complexity"
```

## Project Structure

```
src/devai/
├── core/       # Client, config, models, exceptions
├── prompts/    # PromptTemplate + dev prompt library
├── tools/      # ToolRegistry + code utilities
├── agents/     # Agent + CoderAgent
├── chains/     # Chain, SequentialChain, StructuredChain
├── memory/     # ConversationMemory
├── rag/        # Chunking, VectorStore, RAGChain
├── output/     # JSON/Pydantic parsers
├── utils/      # Token estimation, code extraction
└── cli.py      # Command-line interface
```

## License

MIT
