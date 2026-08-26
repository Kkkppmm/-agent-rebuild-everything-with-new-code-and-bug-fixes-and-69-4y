"""Example: audit pnpm workspace configs with PnpmAnalyzer."""

from devai.pnpm_analyzer import PnpmAnalyzer

analyzer = PnpmAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(analyzer.to_context())
