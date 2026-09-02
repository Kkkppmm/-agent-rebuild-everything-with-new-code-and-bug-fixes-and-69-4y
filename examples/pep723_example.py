"""Example: audit PEP 723 inline script metadata with Pep723Analyzer."""

from devai.pep723_analyzer import Pep723Analyzer

analyzer = Pep723Analyzer(".")
print(analyzer.summary())
print(f"Health score: {analyzer.health_score()}/100")
for finding in analyzer.analyze()[:10]:
    print(finding.format())
