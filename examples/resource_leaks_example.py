"""Example: scan a project for unclosed resource handles."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.resource_leaks(".")
print(analyzer.summary())
for finding in analyzer.high_severity():
    print(finding.format())
