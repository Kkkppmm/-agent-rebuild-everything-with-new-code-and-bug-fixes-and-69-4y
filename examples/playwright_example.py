"""Example: audit Playwright E2E configuration with DevAI."""

from devai import DevAI

dev = DevAI.mock()
analyzer = dev.playwright(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
