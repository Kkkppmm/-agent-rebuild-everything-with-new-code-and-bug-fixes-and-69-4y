"""Example: scan a project for command injection risks."""

from devai import DevAI

ai = DevAI.mock()

# Analyze a directory (defaults to current project)
report = ai.command_injection(".")
print(report.summary())

if report.analyze():
    print("\nFindings:")
    for finding in report.analyze():
        print(f"  {finding.format()}")

# Or run the unified security scan (includes command injection)
scan = ai.security_scan(".")
print(f"\n{scan.summary()}")
