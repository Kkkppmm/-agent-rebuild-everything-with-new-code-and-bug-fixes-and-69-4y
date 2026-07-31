"""Example: scan a project for debug artifacts left in production code."""

from devai import DevAI

ai = DevAI.mock()
detector = ai.debug_artifacts(".")

print(detector.summary())
for finding in detector.high_severity():
    print(finding.format())
