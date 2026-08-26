"""Example: audit Bun configuration with DevAI."""

from devai import DevAI

dev = DevAI.mock()
analyzer = dev.bun(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
