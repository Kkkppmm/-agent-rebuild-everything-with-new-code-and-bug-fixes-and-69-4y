"""Example: audit cibuildwheel pyproject.toml with CibuildwheelAnalyzer."""

from devai.cibuildwheel_analyzer import CibuildwheelAnalyzer

analyzer = CibuildwheelAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(analyzer.to_context())
