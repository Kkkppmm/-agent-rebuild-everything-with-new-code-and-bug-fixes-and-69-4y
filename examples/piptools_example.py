"""Example: audit pip-tools requirements.in and compiled output with PipToolsAnalyzer."""

from devai.piptools_analyzer import PipToolsAnalyzer

analyzer = PipToolsAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(analyzer.to_context())
