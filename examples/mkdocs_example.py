"""Example: audit MkDocs documentation configs with DevAI."""

from devai.mkdocs_analyzer import MkDocsAnalyzer

analyzer = MkDocsAnalyzer(".")
print(analyzer.summary())
print()
print(analyzer.to_context())
