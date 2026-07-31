"""Example: scan a project for SQL injection risks."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.sql_injection(".")
print(analyzer.summary())
for finding in analyzer.high_severity():
    print(finding.format())
