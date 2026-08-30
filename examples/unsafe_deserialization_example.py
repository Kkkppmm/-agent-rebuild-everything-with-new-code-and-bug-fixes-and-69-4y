"""Example: scan for unsafe deserialization patterns."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.unsafe_deserialization(".")
print(analyzer.summary())
