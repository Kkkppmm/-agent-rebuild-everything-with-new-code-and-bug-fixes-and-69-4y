"""Example: audit OpenAPI/Swagger specs with OpenAPIAnalyzer."""

from devai.openapi_analyzer import OpenAPIAnalyzer

analyzer = OpenAPIAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(analyzer.to_context())
