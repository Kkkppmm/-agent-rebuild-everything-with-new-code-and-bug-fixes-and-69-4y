"""Run DevAI programs inline without writing JSON/YAML files."""

from devai import DevAI

ai = DevAI.mock()

# Inline JSON program
results = ai.run_inline(
    """
    {
      "name": "quick-audit",
      "tasks": [
        {"name": "review", "action": "review"},
        {"name": "security", "action": "security"}
      ]
    }
    """,
    {"code": "def add(a, b): return a + b"},
)

for result in results:
    print(f"=== {result.name} ({result.action}) ===")
    print(result.output)

# Inline dict program
plan = ai.dry_run_inline(
    {
        "name": "explain-only",
        "tasks": [{"name": "explain", "action": "explain"}],
    },
    {"code": "x = 1"},
)
print("\nDry-run steps:", [step.action for step in plan])
