"""Example: unified project health dashboard."""

from devai import DevAI, ProjectHealth

# Standalone health analysis (no LLM required)
health = ProjectHealth(".", scan_secrets=True)
report = health.analyze()
print(report.summary())
print()
print(report.to_markdown())

# Via DevAI facade
ai = DevAI.mock()
health_via_facade = ai.health(".")
print(f"Overall score: {health_via_facade.report.overall_score}/100")
