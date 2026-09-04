"""Example: audit GitBook configuration for security risks."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.gitbook(".")

print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())

print("\nHardened template:\n")
print(analyzer.generate_hardened_template())
