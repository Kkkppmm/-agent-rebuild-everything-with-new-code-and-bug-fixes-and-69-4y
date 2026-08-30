"""Audit TypeScript compiler configuration with DevAI."""

from devai import DevAI, TsconfigAnalyzer

analyzer = TsconfigAnalyzer(".")
print(analyzer.summary())

for finding in analyzer.analyze():
    print(finding.format())

# Or use the facade
print(DevAI.mock().tsconfig(".").health_score())
