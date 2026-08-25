"""Example: audit uv pyproject.toml and uv.toml with UvAnalyzer."""

from devai.uv_analyzer import UvAnalyzer

analyzer = UvAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(analyzer.to_context())
