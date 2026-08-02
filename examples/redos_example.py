"""Example: scan for ReDoS (regex denial of service) vulnerabilities."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.redos(".")
print(analyzer.summary())
