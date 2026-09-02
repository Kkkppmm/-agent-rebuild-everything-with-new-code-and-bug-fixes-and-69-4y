"""Example: duplicate code and dead code analysis."""

from devai import DevAI

ai = DevAI.mock()

print("=== Duplicate Code ===")
dupes = ai.duplicates(".", min_lines=5)
print(dupes.summary())
for cluster in dupes.analyze()[:3]:
    print(f"  {cluster.format()}")

print("\n=== Dead Code ===")
dead = ai.dead_code(".")
print(dead.summary())
for symbol in dead.analyze()[:5]:
    print(f"  {symbol.format()}")
