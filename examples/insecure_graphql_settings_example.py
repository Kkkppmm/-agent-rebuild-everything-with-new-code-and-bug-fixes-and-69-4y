"""Example: scan for insecure GraphQL settings."""

from devai import InsecureGraphqlSettingsAnalyzer, SecurityScanner

analyzer = InsecureGraphqlSettingsAnalyzer(".")
print(analyzer.summary())

report = SecurityScanner(".", checks=("insecure_graphql_settings",)).scan()
print(f"Findings: {report.total_findings}")
