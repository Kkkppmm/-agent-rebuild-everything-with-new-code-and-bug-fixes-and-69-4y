"""DevRuntime — unified bootstrap for DevAI programs."""

from devai import DevRuntime

# Bootstrap with mock client (no API key needed)
runtime = DevRuntime.create(use_mock=True)

# Quick one-liner reviews
print(runtime.review("def add(a, b): return a + b"))
print(runtime.explain("async def fetch(): ..."))

# Run a built-in preset program
results = runtime.run(
    "pre-commit",
    {"code": "def process(data):\n    return data"},
)
print(runtime.summarize(results))

# Load and run a custom program from JSON
program = runtime.program("my-audit")
program.add("review", "review").add("security", "security")
results = runtime.run(program, {"code": "x = 1"})
print(f"Ran {len(results)} steps")

# Ollama local setup (requires running Ollama server)
# runtime = DevRuntime.create(provider="ollama", model="llama3.2")
# print(runtime.generate("a Python context manager for temp files"))
