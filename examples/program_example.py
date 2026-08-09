"""Example: declarative DevAI programs for scripted workflows."""

from devai import CodeAssistant, DevProgram
from devai.core import MockLLMClient

assistant = CodeAssistant(client=MockLLMClient(default_response="Looks good."))

# Build a program programmatically
program = (
    DevProgram("pre-commit-audit", assistant)
    .add("review", "review")
    .add("security", "security")
    .add("docstrings", "docstring")
)

code = """
def divide(a, b):
    return a / b
"""

results = program.run({"code": code})
for result in results:
    print(f"[{result.name}] {result.action}: {result.output[:60]}...")

# Or load from JSON
program_json = """
{
  "name": "explain-and-test",
  "tasks": [
    {"name": "explain", "action": "explain"},
    {"name": "tests", "action": "tests", "kwargs": {"framework": "pytest"}}
  ]
}
"""
loaded = DevProgram.from_json(program_json, assistant)
summary = loaded.run_and_summarize({"code": code})
print("\n--- Summary ---\n")
print(summary)
