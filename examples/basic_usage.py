"""Basic DevAI usage examples."""

from devai import CodeAssistant, DevAIConfig, LLMClient, MockLLMClient


def main():
  # Use mock client for demo (no API key needed)
  client = MockLLMClient(default_response="Code looks clean. Consider adding type hints.")
  assistant = CodeAssistant(client=client)

  code = """
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)
"""

  print("=== Code Review ===")
  print(assistant.review(code))

  print("\n=== Explain ===")
  client.responses = ["Recursively computes Fibonacci numbers."]
  print(assistant.explain(code))

  print("\n=== Debug ===")
  client.responses = ["Define variable before use."]
  print(assistant.debug("NameError: n is not defined", "print(n)"))

  print("\n=== With real LLM (uncomment to use) ===")
  print("# config = DevAIConfig.from_env()")
  print("# client = LLMClient(config=config)")
  print("# assistant = CodeAssistant(client=client)")


if __name__ == "__main__":
  main()
