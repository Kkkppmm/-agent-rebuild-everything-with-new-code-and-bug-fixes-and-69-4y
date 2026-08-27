"""Example: audit yamllint configuration with DevAI."""

from devai import DevAI, YamllintAnalyzer

# Direct analyzer usage
analyzer = YamllintAnalyzer(".")
print(analyzer.summary())
print(analyzer.to_context())

# Via DevAI facade
devai = DevAI.mock()
report = devai.yamllint(".").analyze()
print(f"Findings: {len(report)}")

# Generate a hardened template
print(analyzer.generate_hardened_template())
