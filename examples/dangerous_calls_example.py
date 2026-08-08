"""Example: scan a project for dangerous Python calls."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.dangerous_calls(".")
print(analyzer.summary())
for finding in analyzer.high_severity():
    print(finding.format())
