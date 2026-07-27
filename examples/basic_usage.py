"""Basic usage example for DevAI."""

from devai import CodeAssistant
from devai.core import MockLLMClient


def main():
  client = MockLLMClient(responses={
    "review": "Code looks clean. Consider adding type hints.",
    "explain": "This function adds two integers and returns the result.",
  })
  assistant = CodeAssistant(client=client)

  code = """
def add(a, b):
    return a + b
"""

  print("=== Code Review ===")
  print(assistant.review(code))

  print("\n=== Explanation ===")
  print(assistant.explain(code))

  print("\n=== Full Review ===")
  review = assistant.full_review(code)
  for key, value in review.items():
    print(f"\n--- {key} ---")
    print(value[:200])


if __name__ == "__main__":
  main()
