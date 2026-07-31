"""Example: detect async blocking calls and resource leaks."""

from devai import DevAI

ai = DevAI.mock()

print("=== Async Blocking ===")
blocking = ai.async_blocking(".")
print(blocking.summary())
for finding in blocking.high_severity()[:5]:
    print(f"  {finding.format()}")

print("\n=== Resource Leaks ===")
leaks = ai.resource_leaks(".")
print(leaks.summary())
for leak in leaks.high_severity()[:5]:
    print(f"  {leak.format()}")
