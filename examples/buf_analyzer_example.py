"""Example: audit buf.yaml and buf.gen.yaml with BufAnalyzer."""

from devai.buf_analyzer import BufAnalyzer

analyzer = BufAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
print(analyzer.to_context())
