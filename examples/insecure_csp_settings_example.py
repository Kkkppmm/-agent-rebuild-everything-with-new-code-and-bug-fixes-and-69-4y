"""Example: scan for insecure Content-Security-Policy settings."""

from devai import InsecureCspSettingsAnalyzer, SecurityScanner

analyzer = InsecureCspSettingsAnalyzer(".")
print(analyzer.summary())

report = SecurityScanner(".", checks=("insecure_csp_settings",)).scan()
print(f"Findings: {report.total_findings}")
