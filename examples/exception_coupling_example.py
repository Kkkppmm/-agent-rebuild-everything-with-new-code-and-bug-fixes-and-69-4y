"""Example: exception hierarchy and module coupling analysis."""

from devai import DevAI

ai = DevAI.mock(project_path=".")

# Map custom exceptions and risky handlers
exc = ai.exceptions(".")
print(exc.summary())
print(f"Health score: {exc.health_score():.0f}/100")

# Analyze module coupling from import graph
coupling = ai.coupling(".")
print(coupling.summary())
for mod in coupling.unstable_modules()[:5]:
    print(f"  unstable: {mod.format()}")

# Import dependency graph
graph = ai.imports(".")
print(graph.summary())
cycles = graph.find_cycles()
if cycles:
    print("Circular imports detected:")
    for cycle in cycles[:3]:
        print(f"  {' -> '.join(cycle)}")
