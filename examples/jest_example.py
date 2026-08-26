"""Example: audit Jest configuration with DevAI."""

from devai import DevAI

dev = DevAI.mock()
analyzer = dev.jest(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
