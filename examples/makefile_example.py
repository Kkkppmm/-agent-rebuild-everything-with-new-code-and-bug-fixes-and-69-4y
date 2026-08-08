"""Audit Makefiles for security and best practices."""

from devai import DevAI

ai = DevAI()
analyzer = ai.makefile(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
