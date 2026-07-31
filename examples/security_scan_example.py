"""Example: scan for insecure random and path traversal risks."""

from devai import DevAI

ai = DevAI.mock()

print("=== Insecure random ===")
print(ai.insecure_random(".").summary())

print("\n=== Path traversal ===")
print(ai.path_traversal(".").summary())
