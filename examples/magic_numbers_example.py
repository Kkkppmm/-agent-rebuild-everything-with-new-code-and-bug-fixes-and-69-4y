"""Example: detect magic numbers in a Python project."""

from devai import DevAI

ai = DevAI.mock()
detector = ai.magic_numbers(".")
print(detector.summary())
for finding in detector.analyze()[:10]:
    print(finding.format())
