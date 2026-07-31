"""Example: scan a project for blocking calls inside async functions."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.async_blocking(".")
print(analyzer.summary())
for finding in analyzer.high_severity():
    print(finding.format())
