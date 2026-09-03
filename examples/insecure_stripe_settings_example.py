"""Example: scan for insecure Stripe payment API settings."""

from devai import InsecureStripeSettingsAnalyzer, SecurityScanner

checks = ("insecure_stripe_settings",)

scanner = SecurityScanner(".", checks=checks)
report = scanner.scan()
print(report.summary())

analyzer = InsecureStripeSettingsAnalyzer(".")
for finding in analyzer.analyze():
    print(finding.format())
