"""Example: audit PEP 723 inline script metadata with Pep723Analyzer."""

from devai.pep723_analyzer import Pep723Analyzer

analyzer = Pep723Analyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
