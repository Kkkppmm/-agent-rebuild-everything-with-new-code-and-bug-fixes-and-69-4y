"""Example: detect ReDoS-vulnerable regex patterns with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.redos(".")
print(analyzer.summary())
for finding in analyzer.high_severity():
    print(finding.format())
