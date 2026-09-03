"""Quickstart — minimal DevAI setup for developers and programs."""

from devai import DevProgram, quickstart

# One-line bootstrap (mock client — no API key required)
runtime = quickstart(use_mock=True)

code = """
def divide(a, b):
    return a / b
"""

print("=== Quick review ===")
print(runtime.review(code))

print("\n=== Explain ===")
print(runtime.explain(code))

print("\n=== Preset program (pre-commit) ===")
results = runtime.run("pre-commit", {"code": code})
print(runtime.summarize(results))

print("\n=== Custom DevProgram ===")
program = (
    DevProgram("audit", runtime.assistant)
    .add("review", "review")
    .add("security", "security")
)
for step in program.run({"code": code}):
    print(f"[{step.name}] {step.output[:80]}...")
