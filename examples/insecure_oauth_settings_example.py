"""Example: scan for insecure OAuth and social-auth settings."""

from devai import InsecureOAuthSettingsAnalyzer, SecurityScanner

analyzer = InsecureOAuthSettingsAnalyzer(".")
print(analyzer.summary())

report = SecurityScanner(".", checks=("insecure_oauth_settings",)).scan()
print(f"Findings: {report.total_findings}")
