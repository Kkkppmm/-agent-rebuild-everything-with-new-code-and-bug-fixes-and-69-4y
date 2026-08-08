"""Example: audit pre-commit config with DevAI."""

from devai import PrecommitAnalyzer

analyzer = PrecommitAnalyzer(".")
print(analyzer.summary())

if analyzer.stats.config_files:
    print("\nFindings:")
    for finding in analyzer.analyze():
        print(f"  {finding.format()}")

    print("\nLLM context preview:")
    print(analyzer.to_context()[:500], "...")
