"""Example: audit Flit pyproject.toml and flit.ini with DevAI."""

from devai.flit_analyzer import FlitAnalyzer

analyzer = FlitAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze()[:10]:
    print(finding.format())
