"""Example: check PEP 8 naming conventions with DevAI."""

from devai import DevAI

ai = DevAI.mock()

analyzer = ai.naming(".")
print(analyzer.summary())

print("\nClass naming violations:")
for violation in analyzer.by_kind("class"):
    print(f"  {violation.format()}")
