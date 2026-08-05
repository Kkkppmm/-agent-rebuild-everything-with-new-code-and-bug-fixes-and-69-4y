"""Example: detect weak cryptographic algorithms with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.weak_crypto(".")
print(analyzer.summary())
for finding in analyzer.high_severity():
    print(finding.format())
