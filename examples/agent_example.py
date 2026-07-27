"""Agent example with tool calling."""

from devai.agents import CoderAgent
from devai.core import MockLLMClient
from devai.tools import default_registry


def main():
  registry = default_registry()
  agent = CoderAgent(client=MockLLMClient(), tools=registry)

  result = agent.run(
    "Analyze the project structure and list all Python files"
  )
  print("Agent result:")
  print(result)


if __name__ == "__main__":
  main()
