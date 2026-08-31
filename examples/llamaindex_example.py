"""Example: audit a LlamaIndex RAG pipeline with DevAI."""

from devai import LlamaIndexAnalyzer

analyzer = LlamaIndexAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
