# DevAI

A Python AI library built for developers and programmers. DevAI provides a clean, composable toolkit for LLM-powered code review, debugging, refactoring, agents, RAG, and more.

## Features

- **LLM Client** — OpenAI-compatible API with sync/async, streaming, JSON mode, retries, and caching
- **Code Assistant** — High-level facade for review, explain, debug, refactor, security audit, tests, docstrings, API design, SQL optimization, type hints, regex, log analysis, code generation, lint fixes, dependency audits, diff review, performance analysis, Dockerfile review, architecture analysis, and migration planning
- **Structured Output** — Pydantic schemas for code reviews, security audits, and performance analysis
- **CodeProject** — Scan, index, and build context from an entire codebase
- **Observability** — Callback hooks for logging and tracing LLM calls
- **Agents** — Tool-calling agents with a built-in coder agent
- **Chains** — Simple, sequential, and structured (Pydantic) output chains
- **RAG** — Text chunking, vector store, and retrieval-augmented generation
- **Tools** — Code utilities: lint, search, git diff, complexity analysis
- **CLI** — Command-line interface for common developer workflows
- **Pipeline** — Composable review/debug/test workflows

## Installation

```bash
pip install devai

# With OpenAI SDK support
pip install "devai[openai]"

# Development
pip install -e ".[dev]"
```

## Quick Start

```python
from devai import CodeAssistant, CodeProject, CoderAgent, DevAIConfig, MockLLMClient

# Use with any OpenAI-compatible API
config = DevAIConfig(
    api_key="your-api-key",
    base_url="https://api.openai.com/v1",
    model="gpt-4o-mini",
)
assistant = CodeAssistant(config)

# Review code
result = assistant.review("""
def add(a, b):
    return a + b
""")
print(result)

# Explain code
explanation = assistant.explain("async def fetch(): ...")

# Debug an error
fix = assistant.debug(code="...", error="NameError: name 'x' is not defined")

# Generate code from a spec
code = assistant.generate("REST endpoint that returns user profile by ID")

# Structured review with Pydantic output
from devai import CodeReviewResult
result = assistant.structured_review("def foo(): pass")
print(result.score, result.issues)

# Review a git diff
review = assistant.review_diff("diff --git a/app.py ...")

# Batch review multiple files
results = assistant.batch_review({"a.py": "...", "b.py": "..."})
```

## Mock Client (No API Key Required)

```python
from devai import CodeAssistant, MockLLMClient

client = MockLLMClient(default_response="This code looks good.")
assistant = CodeAssistant(client=client)
print(assistant.review("def foo(): pass"))
```

## Agents

```python
from devai import CoderAgent, MockLLMClient
from devai.tools import ToolRegistry, read_file, search_code

registry = ToolRegistry()
registry.register(read_file)
registry.register(search_code)

agent = CoderAgent(client=MockLLMClient(), tools=registry)
response = agent.run("Find all TODO comments in the codebase")
```

## RAG

```python
from devai.rag import chunk_text, VectorStore, RAGChain
from devai.core import MockLLMClient

docs = ["Python uses indentation.", "List comprehensions are concise."]
chunks = chunk_text("\n".join(docs))
store = VectorStore()
store.add_documents(chunks)
chain = RAGChain(client=MockLLMClient(), store=store)
answer = chain.query("How does Python handle blocks?")
```

## CodeProject

```python
from devai import CodeProject, CodeAssistant
from devai.core import MockLLMClient

project = CodeProject("./my-app")
print(project.summary())

# Index for RAG
store = project.to_vector_store()

# Review with project context
assistant = CodeAssistant(client=MockLLMClient())
review = assistant.review_project("./my-app", query="authentication")
```

## Observability

```python
from devai.core import MockLLMClient, LoggingCallback, ObservedLLMClient

callback = LoggingCallback()
client = ObservedLLMClient(MockLLMClient(), callbacks=[callback])
client.complete([...])
print(callback.events)  # [{"event": "start", ...}, {"event": "end", ...}]
```

## CLI

```bash
devai review path/to/file.py
devai explain "def factorial(n): ..."
devai debug --code file.py --error "TypeError: ..."
devai commit --diff "$(git diff)"
devai security path/to/module.py
devai api path/to/routes.py --context "REST API v2"
devai sql "SELECT * FROM users" --context "users table has 1M rows"
devai types path/to/module.py
devai logs error.log
devai project ./my-app --query "error handling"
devai diff --diff "$(git diff)"
devai performance path/to/hot_path.py --context "10k RPS"
devai dockerfile Dockerfile
devai migrate path/to/app.py --source "Django 3" --target "Django 5"
devai generate "REST endpoint for user profiles" --language python
devai fix-lint path/to/module.py "E501 line too long"
devai deps requirements.txt --context "production web app"
devai architecture path/to/main.py --context "microservice"
devai agent "Refactor the auth module"
```

## Configuration

Set environment variables or pass a `DevAIConfig`:

| Variable | Description |
|----------|-------------|
| `DEVAI_API_KEY` | API key for the LLM provider |
| `DEVAI_BASE_URL` | Base URL (default: OpenAI) |
| `DEVAI_MODEL` | Model name (default: `gpt-4o-mini`) |
| `DEVAI_MAX_TOKENS` | Max tokens per request |
| `DEVAI_TEMPERATURE` | Sampling temperature |

## License

MIT
