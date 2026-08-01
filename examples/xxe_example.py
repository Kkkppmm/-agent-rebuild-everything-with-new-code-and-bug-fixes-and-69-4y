"""Example: detect XXE vulnerabilities with DevAI."""

from devai import DevAI

ai = DevAI.mock()
report = ai.xxe(".").analyze()
print(f"Found {len(report)} XXE risks")
print(ai.xxe(".").summary())
