"""Example: detect log injection risks with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.log_injection(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
