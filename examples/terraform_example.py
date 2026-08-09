"""Example: audit Terraform files for security and best practices."""

from devai import TerraformAnalyzer

analyzer = TerraformAnalyzer(".")
print(analyzer.summary())

for finding in analyzer.analyze():
    print(finding.format())

print("\n--- LLM context ---\n")
print(analyzer.to_context())
