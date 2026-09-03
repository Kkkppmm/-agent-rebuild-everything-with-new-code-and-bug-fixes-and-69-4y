"""Audit a LlamaIndex RAG project for security risks."""

from devai import LlamaIndexAnalyzer

analyzer = LlamaIndexAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(f"\nHealth score: {analyzer.health_score()}/100")
