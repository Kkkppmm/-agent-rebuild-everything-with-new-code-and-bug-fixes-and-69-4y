"""Example: scan for exposed Swagger/OpenAPI documentation."""

from devai import InsecureSwaggerSettingsAnalyzer, SecurityScanner

scanner = SecurityScanner(".", checks=("insecure_swagger_settings",))
report = scanner.scan()
print(report.summary())

analyzer = InsecureSwaggerSettingsAnalyzer(".")
for finding in analyzer.analyze():
    print(finding.format())
