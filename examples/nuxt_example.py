"""Audit Nuxt configuration for security and deployment risks."""

from devai import DevAI

analyzer = DevAI.mock().nuxt(".")
print(analyzer.summary())
print(analyzer.to_context())
