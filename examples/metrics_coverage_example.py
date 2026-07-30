"""Example: static code metrics and coverage report analysis."""

from devai import CodeMetrics, CoverageReport, DevAI

# Static metrics — no API key required
metrics = CodeMetrics("src/devai")
print(metrics.summary())
print()
print(metrics.to_context(limit=5))

# AI review of metrics (mock mode)
ai = DevAI.mock()
print(ai.review_metrics("src/devai"))

# Coverage report parsing (provide your coverage.xml path)
# report = CoverageReport("coverage.xml")
# print(report.summary())
# print(ai.review_coverage("coverage.xml"))
