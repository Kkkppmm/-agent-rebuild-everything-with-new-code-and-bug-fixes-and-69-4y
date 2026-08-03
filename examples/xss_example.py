"""Example: detect reflected XSS risks with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.xss(".")
print(analyzer.summary())
for finding in analyzer.high_severity():
    print(finding.format())
