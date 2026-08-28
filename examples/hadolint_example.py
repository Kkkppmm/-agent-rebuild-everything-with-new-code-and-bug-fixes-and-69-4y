"""Audit Hadolint configuration for Dockerfile lint hygiene."""

from devai import DevAI

analyzer = DevAI.mock().hadolint(".")
print(analyzer.summary())
print(analyzer.to_context())
