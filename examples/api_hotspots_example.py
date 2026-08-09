"""Example: API surface and complexity hotspot analysis."""

from devai import DevAI

ai = DevAI.mock()

print("=== Public API Surface ===")
api = ai.api_surface(".", source_dir="src")
print(api.summary())
print()

print("=== Complexity Hotspots ===")
hotspots = ai.hotspots(".", complexity_threshold=10)
print(hotspots.summary())
