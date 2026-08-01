"""Example: scan a project for insecure JWT handling."""

from devai import DevAI

ai = DevAI.mock()

scanner = ai.jwt_security(".")
print(scanner.summary())

for finding in scanner.high_severity():
    print(finding.format())

report = ai.security_scan(".", checks=("jwt_security",))
print(f"\nJWT security score: {report.overall_score}/100")
