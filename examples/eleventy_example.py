"""Example: audit Eleventy (11ty) configuration for security risks."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.eleventy(".")

print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())

print("\nHardened template:\n")
print(analyzer.generate_hardened_template())
