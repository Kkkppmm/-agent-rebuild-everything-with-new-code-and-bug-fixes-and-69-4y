"""Example: unified static security scan across a project."""

from devai import DevAI

ai = DevAI.mock()

report = ai.security_scan(".").scan()
print(report.summary())

if report.total_findings:
    print("\nDetailed context for LLM review:")
    print(ai.security_scan(".").to_context())
