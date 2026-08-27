"""Example: scan for insecure Sentry error tracking settings."""

from devai import InsecureSentrySettingsAnalyzer, SecurityScanner

checks = ("insecure_sentry_settings",)

scanner = SecurityScanner(".", checks=checks)
report = scanner.scan()
print(report.summary())

analyzer = InsecureSentrySettingsAnalyzer(".")
for finding in analyzer.analyze():
    print(finding.format())
