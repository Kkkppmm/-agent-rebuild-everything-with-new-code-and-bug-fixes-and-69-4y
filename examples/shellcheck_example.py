"""Example: audit ShellCheck configuration with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.shellcheck(".")
print(analyzer.summary())
print(analyzer.to_context())
