"""Example: audit Dependabot configuration with DevAI."""

from devai import DevAI

ai = DevAI()
analyzer = ai.dependabot(".")

print(analyzer.summary())
print()
print(analyzer.to_context())
print()
print("Hardened template:")
print(analyzer.generate_hardened_template())
