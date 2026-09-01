"""Audit a Chainlit project for security risks."""

from devai import ChainlitAnalyzer

analyzer = ChainlitAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(f"\nHealth score: {analyzer.health_score()}/100")
