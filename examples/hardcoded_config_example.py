"""Example: detect hardcoded configuration values in a Python project."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.hardcoded_config(".")

print(analyzer.summary())
for finding in analyzer.high_severity():
    print(finding.format())
