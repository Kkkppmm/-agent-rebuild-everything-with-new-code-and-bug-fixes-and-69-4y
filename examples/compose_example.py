"""Audit Docker Compose files for container security issues."""

from devai import DevAI

ai = DevAI()
analyzer = ai.compose(".")
print(analyzer.summary())
for finding in analyzer.analyze()[:10]:
    print(finding.format())
