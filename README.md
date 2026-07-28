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
- **DevProgram** — Declarative JSON programs for scripted multi-step AI workflows
- **DevKit** — Unified developer workspace with built-in presets (pre-commit, release, onboarding, PR review, CI gate)
- **Program Presets** — Ready-made workflows for common developer tasks
- **CI Reporting** — Format structured reviews as GitHub PR comments and Actions annotations
- **Token & Cost Estimation** — Budget LLM usage before sending prompts
- **YAML Programs** — Load DevProgram workflows from YAML files
- **OpenAI Adapter** — Optional official OpenAI SDK integration

## Installation

```bash
pip install devai

# With OpenAI SDK support
pip install "devai[openai]"

# With YAML program support
pip install "devai[yaml]"

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

## DevKit (Unified Workspace)

```python
from devai import DevKit, MockLLMClient

kit = DevKit.from_client(MockLLMClient(default_response="Looks good."))

# Built-in workflows
print(kit.pre_commit("def divide(a, b): return a / b"))
print(kit.audit("class UserService: ..."))
print(kit.onboard("def main(): ..."))

# List and load presets
for preset in kit.presets():
    print(preset["name"], preset["description"])

program = kit.preset("release")
results = kit.run_program(program, {"code": open("app.py").read()})
print(kit.summarize(results))

# Project-aware workflows
kit = DevKit.from_client(MockLLMClient(), project_path="./my-app")
print(kit.review_project(query="authentication"))
```

## CI Integration

```python
from devai import CodeAssistant, report_from_review, MockLLMClient

assistant = CodeAssistant(client=MockLLMClient(...))
review = assistant.structured_review(open("app.py").read())
report = report_from_review(review, fail_below=6)

# Post to GitHub PR
print(report.to_github_comment())

# Use in GitHub Actions
for annotation in report.to_github_annotations():
    print(annotation)
```

```bash
# CLI: generate a CI report
devai ci-report app.py --mode review --fail-below 6
devai ci-report app.py --mode security --format json
devai kit ci-gate path/to/app.py
```

## Token & Cost Estimation

```python
from devai.utils import estimate_tokens, estimate_cost

text = open("large_prompt.txt").read()
print(estimate_tokens(text))  # ~token count
print(estimate_cost(text, model="gpt-4o-mini"))
```

```bash
devai tokens path/to/prompt.txt --model gpt-4o-mini
```

## DevProgram (Scripted Workflows)

```python
from devai import CodeAssistant, DevProgram
from devai.core import MockLLMClient

assistant = CodeAssistant(client=MockLLMClient(default_response="Looks good."))

# Build a program in code
program = (
    DevProgram("pre-commit-audit", assistant)
    .add("review", "review")
    .add("security", "security")
)
results = program.run({"code": open("app.py").read()})

# Or load from JSON or YAML
program = DevProgram.from_file("audit.yaml", assistant)
print(program.run_and_summarize({"code": "..."}))
```

Example `audit.yaml`:

```yaml
name: pre-commit-audit
tasks:
  - name: review
    action: review
  - name: security
    action: security
  - name: smells
    action: code_smell
```

Example `audit.json`:

```json
{
  "name": "pre-commit-audit",
  "tasks": [
    {"name": "review", "action": "review"},
    {"name": "security", "action": "security"}
  ]
}
```

## OpenAI SDK Adapter

```python
from devai.core.config import DevAIConfig
from devai.core.openai_adapter import OpenAIAdapter

adapter = OpenAIAdapter(DevAIConfig(api_key="...", model="gpt-4o-mini"))
response = adapter.complete([Message.user("Hello")])
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
devai openapi path/to/routes.py --context "REST API v2"
devai smells path/to/module.py --focus "complexity, duplication"
devai tokens path/to/prompt.txt --model gpt-4o-mini
devai ci-report path/to/app.py --mode review --fail-below 6
devai agent "Refactor the auth module"
devai run audit.json --code path/to/app.py
devai presets
devai kit audit path/to/app.py
devai kit pre-commit path/to/app.py
devai kit pr-review --project ./my-app --diff "$(git diff)"
devai kit ci-gate path/to/app.py
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
