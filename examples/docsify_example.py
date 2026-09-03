"""Example: audit Docsify index.html configuration for security risks."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.docsify(".")

print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())

print("\nHardened template:\n")
print(analyzer.generate_hardened_template())
