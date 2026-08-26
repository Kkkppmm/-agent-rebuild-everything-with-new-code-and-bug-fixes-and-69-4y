"""Example: audit Cypress E2E configuration with DevAI."""

from devai import DevAI

dev = DevAI.mock()
analyzer = dev.cypress(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
