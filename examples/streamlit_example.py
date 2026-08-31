"""Example: audit a Streamlit project with DevAI."""

from devai import StreamlitAnalyzer

analyzer = StreamlitAnalyzer(".")
print(analyzer.summary())
for finding in analyzer.analyze():
    print(finding.format())
