"""Example: audit HashiCorp Vault configs with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.vault(".")

print(analyzer.summary())
print()
print(analyzer.to_context())
print()
print("Hardened template:")
print(analyzer.generate_hardened_template())
