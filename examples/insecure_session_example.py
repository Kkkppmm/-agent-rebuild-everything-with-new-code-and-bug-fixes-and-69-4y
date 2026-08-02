"""Example: scan a project for insecure session/cookie configuration."""

from devai import DevAI

ai = DevAI.mock()

scanner = ai.insecure_session(".")
print(scanner.summary())

for finding in scanner.high_severity():
    print(finding.format())

report = ai.security_scan(".", checks=("insecure_session",))
print(f"\nInsecure session score: {report.overall_score}/100")
