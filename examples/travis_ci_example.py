"""Example: audit Travis CI configs with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.travis_ci(".")

print(analyzer.summary())
print()
print(analyzer.to_context())
