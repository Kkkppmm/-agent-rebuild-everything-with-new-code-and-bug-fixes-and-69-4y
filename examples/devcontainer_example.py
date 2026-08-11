"""Audit dev container configs with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.devcontainer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
