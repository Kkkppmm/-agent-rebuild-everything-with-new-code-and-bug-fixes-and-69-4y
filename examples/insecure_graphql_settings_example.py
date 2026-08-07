"""Example: scan for insecure GraphQL configuration."""

from devai import InsecureGraphqlSettingsAnalyzer, SecurityScanner

# Standalone analyzer
analyzer = InsecureGraphqlSettingsAnalyzer(".")
for finding in analyzer.analyze():
    print(finding.format())

# Integrated security scan
report = SecurityScanner(".", checks=("insecure_graphql_settings",)).scan()
print(report.summary())
