"""Scaffold a new DevAI-powered Python project."""

from devai import DevAI

result = DevAI.scaffold("./my-ai-app", package="my_ai_app")
print(result.summary())
