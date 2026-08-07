"""Example: scan a project for insecure JWT configuration."""

from devai import InsecureJwtSettingsAnalyzer, SecurityScanner

analyzer = InsecureJwtSettingsAnalyzer(".")
findings = analyzer.analyze()
print(analyzer.summary())
for finding in findings[:10]:
    print(finding.format())

report = SecurityScanner(".", checks=("insecure_jwt_settings",)).scan()
print(f"\nOverall score: {report.overall_score}/100")
