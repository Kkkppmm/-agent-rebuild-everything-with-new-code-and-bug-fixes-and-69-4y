"""Example: analyze static code metrics with DevAI."""

from devai import CodeMetrics, DevAI

# Standalone metrics — no LLM or API key required
metrics = CodeMetrics(".")
metrics.analyze()

print(metrics.summary())
print()
print("Top complex functions:")
for fn in metrics.top_complex(5):
    print(f"  {fn.format()}")

# Via the DevAI facade
ai = DevAI.mock()
project_metrics = ai.metrics(".")
print()
print(project_metrics.to_context(limit=5))

# Export for dashboards or CI
import json

print()
print(json.dumps(project_metrics.to_dict(), indent=2))
