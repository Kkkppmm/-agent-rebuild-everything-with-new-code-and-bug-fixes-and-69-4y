"""Example: audit OPA Rego policies with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.opa(".")

print(analyzer.summary())
print()
print(analyzer.to_context())
print()
print("Hardened template:")
print(analyzer.generate_hardened_template())
