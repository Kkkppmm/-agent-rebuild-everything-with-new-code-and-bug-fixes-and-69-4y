"""Example: scan a project for disabled TLS certificate verification."""

from devai import DevAI

ai = DevAI()
analyzer = ai.insecure_tls(".")
print(analyzer.summary())
