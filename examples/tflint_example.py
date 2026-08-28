"""Example: audit TFLint configuration with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.tflint(".")
print(analyzer.summary())
print(analyzer.to_context())
