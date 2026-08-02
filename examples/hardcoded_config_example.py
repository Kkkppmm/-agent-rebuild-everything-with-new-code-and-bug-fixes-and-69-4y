"""Example: detect hardcoded configuration values."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.hardcoded_config(".")
print(analyzer.summary())
for finding in analyzer.analyze()[:5]:
    print(finding.format())
