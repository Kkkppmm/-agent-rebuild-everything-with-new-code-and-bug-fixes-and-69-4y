# DevAI

A Python AI library built for developers and programmers. DevAI provides a clean, composable toolkit for building AI-powered developer workflows — code review, debugging, refactoring, agents with tool calling, RAG over codebases, and more.

## Features

- **LLM Client** — OpenAI-compatible API with streaming, async, JSON mode, and retries
- **MockLLMClient** — Deterministic responses for testing without API keys
- **CodeAssistant** — High-level facade for common dev tasks (review, explain, debug, refactor, security audit, test generation)
- **Agents** — Tool-calling agent loop with `CoderAgent` for autonomous coding tasks
- **Chains** — Composable prompt chains with structured Pydantic output
- **RAG** — Chunk, embed, and retrieve from documents for context-aware answers
- **Tools** — Built-in utilities: lint Python, search code, read files, git diff, complexity analysis
- **CLI** — `devai review`, `devai explain`, `devai debug`, `devai agent`, and more
- **Pipeline** — Compose multi-step review/debug/test workflows

## Installation

```bash
pip install devai

# With OpenAI support
pip install "devai[openai]"

# Development
pip install -e ".[dev,openai]"
```

## Quick Start

```python
from devai import CodeAssistant, DevAIConfig, MockLLMClient

# Use mock client for testing (no API key needed)
client = MockLLMClient()
assistant = CodeAssistant(client=client)

result = assistant.review("""
def add(a, b):
    return a + b
""")
print(result)
```

### With OpenAI

```python
from devai import CodeAssistant, DevAIConfig, LLMClient

config = DevAIConfig(api_key="sk-...", model="gpt-4o-mini")
client = LLMClient(config=config)
assistant = CodeAssistant(client=client)

print(assistant.explain("async def fetch(url): ..."))
print(assistant.debug(error="NameError: x is not defined", code="print(x)"))
```

### Agent with Tools

```python
from devai.agents import CoderAgent
from devai.tools import ToolRegistry
from devai import MockLLMClient

agent = CoderAgent(
    client=MockLLMClient(),
    tools=ToolRegistry.default(),
)
response = agent.run("Review the complexity of my main.py file")
```

### RAG over Documents

```python
from devai.rag import RAGChain, VectorStore, chunk_text
from devai import MockLLMClient

docs = chunk_text(open("README.md").read())
store = VectorStore()
store.add_documents(docs)
rag = RAGChain(client=MockLLMClient(), store=store)
answer = rag.query("How do I install DevAI?")
```

## CLI

```bash
devai review myfile.py
devai explain "def fib(n): ..."
devai debug --error "TypeError" --code "x + '1'"
devai security src/
devai refactor myfile.py --goal "extract helper functions"
devai agent "find all TODO comments in src/"
```

## Architecture

```
devai/
├── core/        # LLM client, config, models, exceptions
├── prompts/     # Prompt templates for dev tasks
├── tools/       # Tool registry and code utilities
├── agents/      # Agent loop with tool calling
├── chains/      # Composable prompt chains
├── memory/      # Conversation memory
├── rag/         # Retrieval-augmented generation
├── output/      # Structured output parsing
├── utils/       # Token estimation, code extraction
├── assistant.py # High-level CodeAssistant facade
├── pipeline.py  # Multi-step workflows
└── cli.py       # Command-line interface
```

## License

MIT
