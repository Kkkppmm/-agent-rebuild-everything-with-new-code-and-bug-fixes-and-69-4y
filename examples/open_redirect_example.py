"""Example: scan for open redirect vulnerabilities."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.open_redirect(".")
print(analyzer.summary())
