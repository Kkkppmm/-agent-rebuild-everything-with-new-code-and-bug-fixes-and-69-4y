"""Audit dev container configs for security issues."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.devcontainer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
