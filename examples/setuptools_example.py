"""Example: audit setuptools setup.py, setup.cfg, and pyproject.toml with DevAI."""

from devai.setuptools_analyzer import SetuptoolsAnalyzer

analyzer = SetuptoolsAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze()[:10]:
    print(finding.format())
