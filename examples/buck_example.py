"""Audit Buck build configs with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.buck(".")
print(analyzer.summary())
print(analyzer.to_context())
