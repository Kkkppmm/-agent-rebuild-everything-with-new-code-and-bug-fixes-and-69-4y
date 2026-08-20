"""Audit Docker Compose files for security and best practices."""

from devai import DevAI

ai = DevAI()
analyzer = ai.compose(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
