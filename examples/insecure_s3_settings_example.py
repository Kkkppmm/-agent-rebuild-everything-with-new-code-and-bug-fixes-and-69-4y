"""Example: scan for insecure AWS S3 / object storage settings."""

from devai import InsecureS3SettingsAnalyzer, SecurityScanner

checks = ("insecure_s3_settings",)

scanner = SecurityScanner(".", checks=checks)
report = scanner.scan()
print(report.summary())

analyzer = InsecureS3SettingsAnalyzer(".")
for finding in analyzer.analyze():
    print(finding.format())
