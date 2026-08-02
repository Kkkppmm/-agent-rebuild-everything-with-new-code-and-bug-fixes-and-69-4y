"""Unsafe deserialization detection example."""

from devai import DevAI

ai = DevAI()
analyzer = ai.unsafe_deserialization(".")
print(analyzer.summary())
