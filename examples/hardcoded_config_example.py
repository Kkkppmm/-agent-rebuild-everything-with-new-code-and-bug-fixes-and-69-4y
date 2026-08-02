"""Hardcoded configuration detection example."""

from devai import DevAI

ai = DevAI()
analyzer = ai.hardcoded_config(".")
print(analyzer.summary())
