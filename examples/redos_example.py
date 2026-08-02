"""ReDoS (regex denial-of-service) detection example."""

from devai import DevAI

ai = DevAI()
analyzer = ai.redos(".")
print(analyzer.summary())
