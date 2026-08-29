"""Example: scan for insecure Elasticsearch configuration."""

from devai import InsecureElasticsearchSettingsAnalyzer, SecurityScanner

scanner = SecurityScanner(".", checks=("insecure_elasticsearch_settings",))
report = scanner.scan()
print(report.summary())

analyzer = InsecureElasticsearchSettingsAnalyzer(".")
for finding in analyzer.analyze():
    print(finding.format())
