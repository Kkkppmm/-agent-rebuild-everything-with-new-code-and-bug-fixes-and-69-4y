"""Detect insecure secret comparisons vulnerable to timing attacks."""

from devai import DevAI

ai = DevAI()
analyzer = ai.timing_attack(".")
print(analyzer.summary())
for finding in analyzer.high_severity():
    print(finding.format())
