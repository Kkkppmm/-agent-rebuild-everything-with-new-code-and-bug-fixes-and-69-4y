"""Example: detect SSRF risks with DevAI."""

from devai import DevAI

ai = DevAI.mock()

analyzer = ai.ssrf(".")
print(analyzer.summary())

for finding in analyzer.high_severity():
    print(finding.format())
