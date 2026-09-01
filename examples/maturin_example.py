"""Example: audit maturin pyproject.toml and Cargo.toml with MaturinAnalyzer."""

from devai.maturin_analyzer import MaturinAnalyzer

analyzer = MaturinAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(analyzer.to_context())
