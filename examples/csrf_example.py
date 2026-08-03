"""Example: detect missing CSRF protection with DevAI."""

from devai import DevAI

ai = DevAI()
report = ai.csrf(".").analyze()
print(f"Found {len(report)} CSRF risks")
for finding in report:
    print(finding.format())
