"""Example: audit Deno configuration with DevAI."""

from devai import DevAI

dev = DevAI.mock()
analyzer = dev.deno(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
