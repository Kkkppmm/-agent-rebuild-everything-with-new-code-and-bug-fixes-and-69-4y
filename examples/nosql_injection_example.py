"""Example: scan a project for NoSQL injection risks."""

from devai import DevAI

ai = DevAI.mock()

scanner = ai.nosql_injection(".")
print(scanner.summary())

for finding in scanner.high_severity():
    print(finding.format())

report = ai.security_scan(".", checks=("nosql_injection",))
print(f"\nNoSQL injection score: {report.overall_score}/100")
