"""Terraform audit example."""

from devai import TerraformAnalyzer

analyzer = TerraformAnalyzer(".")
print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")

for finding in analyzer.analyze()[:10]:
    print(finding.format())
