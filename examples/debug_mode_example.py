"""Example: scan a project for debug mode in production."""

from devai import DevAI

ai = DevAI.mock()

scanner = ai.debug_mode(".")
print(scanner.summary())

for finding in scanner.high_severity():
    print(finding.format())

report = ai.security_scan(".", checks=("debug_mode",))
print(f"\nDebug mode score: {report.overall_score}/100")
