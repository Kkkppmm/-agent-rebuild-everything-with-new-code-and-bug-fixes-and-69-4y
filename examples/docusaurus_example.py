"""Example: audit Docusaurus configuration with DevAI."""

from devai import DevAI

ai = DevAI.mock()
analyzer = ai.docusaurus(".")

print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in analyzer.analyze():
    print(finding.format())

# Generate a hardened starter config:
# print(analyzer.generate_hardened_template())
