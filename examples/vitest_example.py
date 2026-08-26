"""Example: audit Vitest configuration with DevAI."""

from devai import DevAI

dev = DevAI.mock()
analyzer = dev.vitest(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
