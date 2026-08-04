"""Run DevAI programs inline without writing JSON/YAML files."""

from devai import DevAI

ai = DevAI.mock()

# Inline dict program
inline = {
    "name": "quick-audit",
    "tasks": [
        {"name": "review", "action": "review"},
        {"name": "security", "action": "security"},
    ],
}
results = ai.run_inline(inline, {"code": "def add(a, b): return a + b"})
for result in results:
    print(f"{result.name}: {result.output[:80]}...")

# Inline JSON text
json_program = """
{
  "name": "explain-only",
  "tasks": [{"name": "explain", "action": "explain"}]
}
"""
results = ai.run_inline(json_program, {"code": "x = sum(range(10))"})
print(results[0].output)

# Run a preset directly on a source file
from pathlib import Path

sample = Path(__file__).parent / "basic_usage.py"
if sample.exists():
    file_results = ai.run_on_file("pre-commit", sample)
    print(f"Reviewed {sample.name}: {len(file_results)} steps")

# One-liner quick action
print(ai.quick_action("review", "def foo(): pass"))
