"""Audit a LangChain agent or RAG project for security risks."""

from devai import LangChainAnalyzer

analyzer = LangChainAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(f"\nHealth score: {analyzer.health_score()}/100")
