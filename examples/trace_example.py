"""Tracing DevAI program execution."""

from devai import quickstart

runtime = quickstart(use_mock=True)
runtime.trace.clear()

results = runtime.run(
    "pre-commit",
    {"code": "def add(a, b): return a + b"},
    trace=True,
)

print(f"Ran {len(results)} steps")
print(runtime.trace.to_json())
