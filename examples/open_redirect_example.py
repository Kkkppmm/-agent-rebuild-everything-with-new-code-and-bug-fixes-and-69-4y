"""Open redirect vulnerability detection example."""

from devai import DevAI

ai = DevAI()
analyzer = ai.open_redirect(".")
print(analyzer.summary())
