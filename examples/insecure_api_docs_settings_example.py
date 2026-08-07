"""Example: scan for exposed API documentation configuration."""

from devai import InsecureApiDocsSettingsAnalyzer, SecurityScanner

analyzer = InsecureApiDocsSettingsAnalyzer(".")
print(analyzer.summary())

report = SecurityScanner(".", checks=("insecure_api_docs_settings",)).scan()
print(report.summary())
