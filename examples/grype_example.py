"""Audit Grype ignore files and CLI configs for security issues."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.grype(".")

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in analyzer.analyze():
    print(finding.format())
