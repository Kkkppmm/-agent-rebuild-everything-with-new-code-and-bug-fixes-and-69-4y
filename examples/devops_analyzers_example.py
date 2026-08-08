"""Example: audit Docker Compose, GitHub Actions, pre-commit, and Makefiles."""

from devai import (
    ComposeAnalyzer,
    MakefileAnalyzer,
    PrecommitAnalyzer,
    ProjectHealth,
    WorkflowAnalyzer,
)

root = "."

print("=== Compose ===")
compose = ComposeAnalyzer(root)
print(compose.summary())
for finding in compose.analyze()[:5]:
    print(f"  {finding.format()}")

print("\n=== Workflows ===")
workflow = WorkflowAnalyzer(root)
print(workflow.summary())

print("\n=== Pre-commit ===")
precommit = PrecommitAnalyzer(root)
print(precommit.summary())

print("\n=== Makefile ===")
makefile = MakefileAnalyzer(root)
print(makefile.summary())

print("\n=== Project Health (includes all analyzers) ===")
health = ProjectHealth(root, scan_secrets=False)
print(health.summary())
