"""Example: scan for insecure Sentry SDK configuration."""

from devai import InsecureSentrySettingsAnalyzer, SecurityScanner

analyzer = InsecureSentrySettingsAnalyzer(".")
print(analyzer.summary())

report = SecurityScanner(".", checks=("insecure_sentry_settings",)).scan()
print(report.summary())
