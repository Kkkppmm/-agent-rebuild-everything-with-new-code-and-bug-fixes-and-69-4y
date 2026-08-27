"""Example: audit ShellCheck configuration with DevAI."""

from devai import DevAI, ShellcheckAnalyzer

devai = DevAI.mock()
analyzer = ShellcheckAnalyzer(".")
print(analyzer.summary())

report = devai.shellcheck(".").analyze()
print(f"Findings: {len(report)}")
