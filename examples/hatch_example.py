"""Example: audit Hatch pyproject.toml and hatch.toml with HatchAnalyzer."""

from devai.hatch_analyzer import HatchAnalyzer

analyzer = HatchAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze()[:10]:
    print(finding.format())
