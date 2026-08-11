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
- **RAG** — Text chunking, TF-IDF vector store, embedding-based semantic search, and retrieval-augmented generation
- **Code Sandbox** — Run generated Python code in an isolated subprocess with timeout and test verification
- **Plugins** — Register custom actions for DevProgram workflows
- **Tools** — Code utilities: lint, search, git diff, complexity analysis
- **CLI** — Command-line interface for common developer workflows
- **Pipeline** — Composable review/debug/test workflows
- **DevProgram** — Declarative JSON/YAML programs for scripted multi-step AI workflows
- **DevKit** — Unified developer workspace with built-in presets (pre-commit, release, onboarding, PR review)
- **CI Integration** — GitHub Actions annotations, PR comments, and CI gate helpers
- **Cost Estimation** — Token counting and per-model cost estimates
- **DevWorkflow** — Orchestrate multiple programs with sequential and parallel execution
- **Program Presets** — Ready-made workflows (pre-commit, release, CI gate, incident response, dependency update, docs-gen, test-gen, hotfix, api-review, sql-review)
- **DevRuntime** — One-line bootstrap for programs, presets, and quick dev workflows
- **Local LLM Support** — Ollama and any OpenAI-compatible endpoint via config presets
- **Program Validation** — Validate JSON/YAML program files before execution
- **DevApp** — Build and ship AI-powered CLI tools from programs
- **Program Dry-Run** — Preview execution steps without calling the LLM
- **Program Schema** — JSON Schema for IDE validation of program files
- **Rate Limiting** — Token-bucket rate limiter and `RateLimitedLLMClient` for batch jobs and agents
- **Circuit Breaker** — Prevent cascading failures when LLM providers are down
- **Metrics** — Collect latency, throughput, and error metrics for LLM calls
- **DevSchedule** — Cron-like scheduling for programs and workflows
- **Resilient Client** — One-line wrapper combining rate limiting, circuit breaker, and metrics
- **Health Checks** — Verify LLM provider connectivity before running jobs
- **Quickstart** — `quickstart()` and `assistant()` helpers for minimal setup
- **GitContext** — One-line git-aware reviews, commit messages, and PR descriptions
- **DevTrace** — Lightweight tracing spans for program steps and workflows
- **Program Templates** — `${var:}`, `${env:}`, and `${file:}` interpolation in program context
- **Project Config Files** — Load `.devai.yaml` / `devai.json` for per-project LLM settings
- **Benchmarking** — Measure LLM latency, p95, and throughput with `BenchmarkRunner`
- **DevDoctor** — Environment diagnostics for Python version, dependencies, API keys, and provider health
- **ProgramReport** — Export program and workflow results to JSON or Markdown
- **Disk Cache** — `DiskCachedLLMClient` persists LLM responses to disk for faster dev iteration
- **Token Budget** — `TokenBudget` and `BudgetedLLMClient` track and enforce token/cost limits
- **DevWatcher** — Poll directories and auto-run presets when code files change
- **DevContext** — Fluent builder for assembling LLM context from files, snippets, git diffs, and variables
- **PromptBuilder** — Structured prompt assembly with system/user messages, context, and few-shot examples
- **ProgramLibrary** — Discover, search, and run JSON/YAML programs from a directory
- **Program Export** — Export DevProgram files to standalone runnable Python scripts
- **BatchReviewer** — Review multiple files or entire directories in parallel
- **Code Block Extraction** — Pull fenced code blocks from LLM responses with `extract_code_blocks()`
- **Fallback Client** — `FallbackLLMClient` tries multiple providers/models in order on failure
- **Patch Application** — Apply unified diffs from LLM output with `apply_unified_diff()`
- **CodeSymbolIndex** — AST-based symbol indexer for Python projects with search and LLM context export
- **Conversation Persistence** — Save and load `ConversationMemory` to JSON files
- **OpenAPI Review** — Review OpenAPI/Swagger specs for design, security, and consistency issues
- **Jupyter Notebooks** — Read, extract, and review `.ipynb` notebooks with `NotebookReader` and `review_notebook()`
- **Test Failure Analysis** — Analyze pytest/unittest output with `analyze_test_failures()`
- **Stack Trace Analysis** — Debug crashes with `analyze_stacktrace()`
- **ProgramComposer** — Fluent Python API for building DevProgram workflows without JSON/YAML
- **Schedule Config** — Load cron job definitions from JSON/YAML files for DevSchedule and ProgramLibrary
- **ImportGraph** — Analyze Python import dependencies, find circular imports, and export LLM context
- **SecretsScanner** — Heuristic scan for hardcoded API keys, tokens, and credentials
- **GitChangelog** — Generate Keep a Changelog-style release notes from git commit history
- **TypingCoverage** — Analyze type hint coverage across Python projects and export LLM context
- **EnvVarAnalyzer** — Inventory environment variables, detect drift between code and `.env.example`, and scaffold env templates
- **GitignoreAnalyzer** — Audit `.gitignore` coverage, recommend patterns by language, and detect exposed sensitive files
- **DockerfileAnalyzer** — Audit Dockerfiles for security risks (root user, :latest tags, secrets in ENV) and container best practices
- **WorkflowAnalyzer** — Audit GitHub Actions workflows for unpinned actions, pull_request_target misuse, broad permissions, and script injection
- **AzurePipelinesAnalyzer** — Audit Azure Pipelines for hardcoded secrets, unpinned tasks, privileged containers, and unsafe PR checkout patterns
- **TravisCIAnalyzer** — Audit Travis CI configs for hardcoded secrets, curl-pipe-to-shell, cleartext deploy keys, and unpinned language versions
- **BuildkiteAnalyzer** — Audit Buildkite pipelines for hardcoded secrets, unpinned plugins, privileged Docker, and environment propagation
- **CodefreshAnalyzer** — Audit Codefresh pipelines for hardcoded secrets, CF_* injection, privileged containers, and unencrypted exports
- **SemaphoreCIAnalyzer** — Audit Semaphore CI pipelines for hardcoded secrets, auto-promote rules, SEMAPHORE_* injection, and privileged containers
- **ConcourseCIAnalyzer** — Audit Concourse CI pipelines for hardcoded secrets, privileged tasks, insecure_skip_verify, and variable injection in run scripts
- **TektonAnalyzer** — Audit Tekton Pipeline/Task YAML for hardcoded secrets, hostPath mounts, privileged securityContext, and parameter injection in scripts
- **ArgoWorkflowsAnalyzer** — Audit Argo Workflows YAML for hardcoded secrets, hostNetwork/hostPID, privileged securityContext, and expression injection in scripts
- **FluxCDAnalyzer** — Audit Flux CD GitOps manifests for insecure HTTP sources, disabled TLS verification, force apply, cluster-admin RBAC, and hardcoded secrets
- **ArgoCDAnalyzer** — Audit Argo CD Application/ApplicationSet manifests for insecure sources, wildcard destinations, weak sync policies, and hardcoded credentials
- **AWSCodeBuildAnalyzer** — Audit AWS CodeBuild buildspec files for hardcoded secrets, unencrypted artifacts, privileged Docker, and CODEBUILD_* injection
- **DevContainerAnalyzer** — Audit dev container configs for hardcoded secrets, privileged mode, docker.sock mounts, and unsafe lifecycle commands
- **AWSCodePipelineAnalyzer** — Audit AWS CodePipeline configs for hardcoded secrets, disabled encryption, wildcard IAM, and missing production approvals
- **HarnessCIAnalyzer** — Audit Harness CI pipeline YAML for hardcoded secrets, privileged containers, automountServiceAccountToken, and Harness expression injection
- **BuddyCIAnalyzer** — Audit Buddy CI pipeline YAML for hardcoded secrets, docker_privileged_mode, unpinned image tags, and Buddy variable injection
- **DependabotAnalyzer** — Audit `.github/dependabot.yml` for hardcoded registry credentials, insecure external code execution, daily update floods, and missing security groups
- **RenovateAnalyzer** — Audit `renovate.json` for hardcoded host rule tokens, disabled vulnerability alerts, unsafe automerge, and post-upgrade shell tasks
- **SnykAnalyzer** — Audit `.snyk` and `snyk.yaml` for hardcoded tokens, wildcard vulnerability ignores, missing expiry dates, and lowered severity thresholds
- **AppVeyorCIAnalyzer** — Audit AppVeyor CI configs for hardcoded secrets, enable_rdp, cleartext deploy api_key, and APPVEYOR_* variable injection
- **GoCDCIAnalyzer** — Audit GoCD pipeline YAML for hardcoded secrets, privileged containers, insecure_skip_verify, and GO_* variable injection
- **CirrusCIAnalyzer** — Audit Cirrus CI `.cirrus.yml` for hardcoded secrets, privileged containers, skip_tls_verify, and CIRRUS_* variable injection
- **ComposeAnalyzer** — Audit Docker Compose files for privileged mode, host mounts, :latest tags, secrets in environment, and missing resource limits
- **PrecommitAnalyzer** — Audit `.pre-commit-config.yaml` for unpinned hook revisions, local hooks with unsafe entries, and secrets in config
- **DependencyParser** — Parse requirements.txt and pyproject.toml, detect unpinned and duplicate deps
- **StreamCollector** — Collect streaming LLM output with callbacks, timing, and chunk storage
- **DevHooks** — Install git pre-commit, pre-push, commit-msg, and post-commit hooks powered by DevAI presets
- **Async Batch Review** — `areview_files()` and `areview_directory()` for async parallel file reviews
- **CodeComparer** — Compare two files or code strings, generate unified diffs, and AI-review changes
- **PromptRegistry** — Discover and register custom prompt templates alongside built-in DevAI prompts
- **ProjectDetector** — Detect project language, framework, package manager, and tooling from a directory
- **CodeMetrics** — Static analysis for LOC, cyclomatic complexity, and function counts without LLM calls
- **DocstringCoverage** — Analyze docstring coverage for functions, methods, and classes
- **TestMapper** — Map source modules to test files and find untested modules
- **Async Facade** — `areview()` and `aexplain()` async methods on the `DevAI` entry point
- **ProjectHealth** — Unified project health dashboard combining metrics, typing, docstrings, tests, dependencies, secrets, env vars, gitignore, dockerfile, code smells, tech-debt, exceptions, and coupling analysis with scored recommendations
- **CodeSmellDetector** — AST-based detection of long functions, deep nesting, bare except, god classes, and excessive parameters
- **TechDebtScanner** — Scan for TODO, FIXME, HACK, XXX, and other tech-debt comment markers across multiple languages
- **DuplicateCodeDetector** — Find duplicate and near-duplicate code blocks using normalized line hashing
- **DeadCodeAnalyzer** — Detect potentially unused top-level Python functions and classes
- **APISurfaceAnalyzer** — Map public API symbols, check `__all__` declarations, and flag undocumented exports
- **ComplexityHotspotAnalyzer** — Rank files by complexity debt to prioritize refactoring
- **ExceptionHierarchyAnalyzer** — Map custom exception classes, inheritance chains, and risky bare/broad except handlers
- **ModuleCouplingAnalyzer** — Measure afferent/efferent coupling and instability from import graphs
- **NamingConventionAnalyzer** — Check PEP 8 naming for functions, methods, classes, variables, and constants
- **MagicNumberDetector** — Find unexplained numeric literals that should be named constants
- **DangerousCallsAnalyzer** — Detect risky calls (`eval`, `exec`, `shell=True`) and mutable default arguments
- **WeakCryptoAnalyzer** — Detect MD5, SHA1, and weak ciphers used for security-sensitive operations
- **LogInjectionAnalyzer** — Detect dynamic log messages that enable log injection attacks
- **SQLInjectionAnalyzer** — Detect dynamic SQL construction in database execute calls
- **DebugArtifactDetector** — Find print, breakpoint, and pdb debug code left in sources
- **AsyncBlockingDetector** — Detect blocking calls inside async functions
- **ResourceLeakAnalyzer** — Detect files, sockets, and connections opened without context managers
- **InsecureRandomAnalyzer** — Detect use of `random` for tokens, passwords, and other security-sensitive values
- **PathTraversalAnalyzer** — Detect unsafe file path construction from user-controlled input
- **CommandInjectionAnalyzer** — Detect dynamic shell command construction in os/subprocess calls
- **SSRFAnalyzer** — Detect server-side request forgery risks in outbound HTTP client calls
- **SecurityScanner** — Unified static security scan combining secrets, injections, dangerous calls, insecure random, weak crypto, log injection, SSRF, path traversal, and 77 security checks
- **ProxyTrustAnalyzer** — Detect unvalidated trust of X-Forwarded-For and proxy headers for client IP and access control
- **InsecureWebSocketAnalyzer** — Detect hardcoded ws:// URLs and disabled WebSocket TLS in real-time applications
- **InsecureMiddlewareSettingsAnalyzer** — Detect missing SecurityMiddleware, CSRF, and clickjacking middleware in Django production settings
- **InsecureRestFrameworkSettingsAnalyzer** — Detect AllowAny defaults, missing auth/throttle classes, and BrowsableAPIRenderer in Django REST Framework settings
- **InsecureCelerySettingsAnalyzer** — Detect pickle serializers, task_always_eager, and unauthenticated Redis/AMQP broker URLs in Celery settings
- **InsecureGraphqlSettingsAnalyzer** — Detect enabled introspection, playground/GraphiQL, and debug mode in GraphQL settings
- **InsecureWebhookSettingsAnalyzer** — Detect disabled signature verification and weak/empty webhook secrets
- **InsecureJwtSettingsAnalyzer** — Detect disabled JWT verification, 'none' algorithm, and weak signing keys in settings

## Installation

```bash
pip install devai

# With OpenAI SDK support
pip install "devai[openai]"

# With YAML program support
pip install "devai[yaml]"
```

## Quick Start

```python
from devai import DevAI

# Fastest path — mock mode, no API key required
ai = DevAI.mock()
print(ai.review("def add(a, b): return a + b"))
```

```python
from devai import quickstart

# Full runtime with programs, presets, and workflows
runtime = quickstart(use_mock=True)
print(runtime.review("def add(a, b): return a + b"))
```

```python
from devai import quickstart

# Review local git changes
runtime = quickstart(use_mock=True)
print(runtime.review_git(staged=True))

# Trace program execution
runtime.trace.clear()
runtime.run("pre-commit", {"code": "x = 1"}, trace=True)
print(runtime.trace.summary())
```

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

## DevRuntime (Fastest Start)

```python
from devai import DevRuntime

# Bootstrap everything in one line (mock mode — no API key)
runtime = DevRuntime.create(use_mock=True)

print(runtime.review("def add(a, b): return a + b"))
print(runtime.generate("a context manager for temp files"))

# Run a built-in preset program
results = runtime.run("pre-commit", {"code": "def foo(): pass"})
print(runtime.summarize(results))

# Local Ollama (requires running Ollama server)
# runtime = DevRuntime.create(provider="ollama", model="llama3.2")
```

## Project Config Files

```bash
devai config-init              # creates .devai.yaml
devai config-show              # show resolved settings
```

```python
from devai import DevRuntime, load_config_file

# Load from .devai.yaml / devai.json in the project root
runtime = DevRuntime.from_project("./my-app")
config = load_config_file()    # raises if no config file is found
```

Example `.devai.yaml`:

```yaml
provider: openai
model: gpt-4o-mini
temperature: 0.2
max_tokens: 4096
# api_key: sk-...  # or set DEVAI_API_KEY
```

## Benchmarking

```python
from devai import BenchmarkRunner, DevRuntime

runtime = DevRuntime.create(use_mock=True)
result = BenchmarkRunner(runtime.client).run(iterations=10)
print(result.summary())   # mean/p95 latency and throughput
```

```bash
devai benchmark --mock --iterations 10
devai benchmark --provider openai --iterations 5 --json
```

## Health Checks

```python
from devai import check_health

result = check_health(use_mock=True)
print(result.healthy, result.latency_ms)

# CLI: devai health --mock
# devai health --provider ollama --no-probe
```

## DevApp (Ship Your Own Tool)

```python
from devai import DevApp

# Build a code auditor app in a few lines
app = (
    DevApp.create(name="code-auditor", use_mock=True)
    .use_preset("pre-commit")
    .with_context(code=open("app.py").read())
)

results = app.run()
print(app.summarize(results))

# Or expose as a CLI
# app.cli(["--dry-run", "--code", "app.py"])
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

## Semantic RAG (Embeddings)

```python
from devai import MockEmbeddingClient, MockLLMClient
from devai.rag import SemanticVectorStore, SemanticRAGChain

store = SemanticVectorStore(MockEmbeddingClient())
store.add_texts(["DevAI helps developers with code review and agents."])
chain = SemanticRAGChain(MockLLMClient(), store)
answer = chain.query("What does DevAI do?")
```

## Code Sandbox

```python
from devai import CodeAssistant, MockLLMClient
from devai.sandbox import CodeSandbox

sandbox = CodeSandbox()
result = sandbox.run_python("print('hello')")

assistant = CodeAssistant(client=MockLLMClient(default_response="def add(a,b): return a+b"))
verified = assistant.generate_and_verify("add two numbers", "assert add(1,2)==3")
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

## DevWorkflow (Multi-Program Orchestration)

```python
from devai import DevRuntime, DevWorkflow

runtime = DevRuntime.create(use_mock=True)

# Chain multiple presets sequentially
workflow = (
    runtime.workflow("ship-it")
    .add("quality", "pre-commit")
    .add("docs", "docs-gen")
)
result = workflow.run({
    "code": "def add(a, b): return a + b",
    "project": "mylib",
    "description": "A tiny math library",
})
print(result.summarize())

# Run independent checks in parallel
parallel = (
    DevWorkflow("gate", runtime.assistant)
    .add_parallel("checks", ("review", "pre-commit"), ("hotfix", "hotfix"))
)
parallel.run({"code": "def foo(): pass"})
```

```bash
# CLI: run a workflow from presets
devai workflow quality:pre-commit docs:docs-gen --code app.py --mock
devai workflow review:pre-commit security:security-deep-dive --parallel --mock
```

## DevSchedule (Cron Automation)

```python
from devai import DevRuntime

runtime = DevRuntime.create(use_mock=True)
schedule = runtime.schedule()
schedule.add("nightly", "0 2 * * *", "nightly-audit")
schedule.add("hourly", "0 * * * *", "code-health")

# Run immediately
result = schedule.run_once("hourly", {"code": "def foo(): pass"})

# Resilient client with rate limiting + circuit breaker + metrics
client = runtime.resilient_client(requests_per_minute=120)
```

```bash
# Validate and run scheduled presets
devai cron-validate "0 * * * *" --check
devai schedule pre-commit --cron "0 * * * *" --once --code app.py --mock
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

# Or load from JSON
program = DevProgram.from_file("audit.json", assistant)
print(program.run_and_summarize({"code": "..."}))

# Or load from YAML (requires pip install 'devai[yaml]')
program = DevProgram.from_file("audit.yaml", assistant)
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

## CI Integration

```python
from devai import CIReporter, CodeAssistant, MockLLMClient

reporter = CIReporter(CodeAssistant(client=MockLLMClient()))
payload = reporter.run_program_for_ci("pre-commit", {"code": open("app.py").read()})

print(payload["pr_comment"])       # GitHub PR comment markdown
print(payload["annotations"])      # GitHub Actions ::warning:: lines
print(payload["passed"])           # CI gate result
```

```bash
devai ci --preset pre-commit --code app.py
devai ci --program audit.yaml --code app.py --format comment
```

## Cost Estimation

```python
from devai.core.models import Message
from devai.utils import estimate_message_cost, format_cost

cost = estimate_message_cost(
    [Message.user("Review this code")],
    response="Looks good.",
    model="gpt-4o-mini",
)
print(format_cost(cost))
```

## Doctor & Reports

```python
from devai import DevDoctor, ProgramReport, quickstart

# Diagnose your environment
doctor = DevDoctor()
print(doctor.summary())

# Run a program and export results
runtime = quickstart(use_mock=True)
results = runtime.run("pre-commit", {"code": "def foo(): pass"})
print(runtime.report(results, format="markdown"))
print(runtime.report(results, format="json"))

report = ProgramReport.from_program_results(results, program_name="pre-commit")
print(report.to_markdown())
```

```bash
devai doctor
devai doctor --json
devai report pre-commit app.py --format json
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
devai workflow-audit .
devai compose-audit .
devai precommit-audit .
devai migrate path/to/app.py --source "Django 3" --target "Django 5"
devai generate "REST endpoint for user profiles" --language python
devai fix-lint path/to/module.py "E501 line too long"
devai deps requirements.txt --context "production web app"
devai architecture path/to/main.py --context "microservice"
devai agent "Refactor the auth module"
devai run audit.json --code path/to/app.py
devai validate audit.json
devai dry-run audit.json --code path/to/app.py
devai schema
devai presets
devai kit audit path/to/app.py
devai kit pre-commit path/to/app.py
devai kit pr-review --project ./my-app --diff "$(git diff)"
devai ci --preset pre-commit --code app.py
devai config-init
devai config-show
devai benchmark --mock --iterations 5
devai health --mock
```

## Configuration

Set environment variables, create a project config file (`.devai.yaml`), or pass a `DevAIConfig`:

| Variable | Description |
|----------|-------------|
| `DEVAI_API_KEY` | API key for the LLM provider |
| `DEVAI_BASE_URL` | Base URL (default: OpenAI) |
| `DEVAI_MODEL` | Model name (default: `gpt-4o-mini`) |
| `DEVAI_MAX_TOKENS` | Max tokens per request |
| `DEVAI_TEMPERATURE` | Sampling temperature |

## License

MIT
