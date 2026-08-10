"""Audit Jenkinsfiles for security and CI best practices."""

from devai import DevAI

ai = DevAI.mock()

analyzer = ai.jenkinsfile(".")
print(analyzer.summary())

for finding in analyzer.analyze():
    print(finding.format())

print("\n--- Hardened template ---\n")
print(analyzer.generate_hardened_template())
