"""Audit Qwik City configuration for security risks."""

from devai import DevAI

analyzer = DevAI.mock().qwik(".")
print(analyzer.summary())
print()
print(analyzer.to_context())
