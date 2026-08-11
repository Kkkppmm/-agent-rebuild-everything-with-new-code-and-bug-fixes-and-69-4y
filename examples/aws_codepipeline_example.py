"""Example: audit AWS CodePipeline configs with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.aws_codepipeline(".")

print(analyzer.summary())
print()
print(analyzer.to_context())
