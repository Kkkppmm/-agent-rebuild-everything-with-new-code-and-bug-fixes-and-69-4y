"""Agent with tool calling example."""

from devai.agents import CoderAgent
from devai.core.client import MockLLMClient
from devai.core.models import ToolCall
from devai.tools import ToolRegistry


def main():
  # Simulate agent using tools then responding
  registry = ToolRegistry.default()
  client = MockLLMClient(
    tool_responses=[
      [ToolCall(id="1", name="list_files", arguments={"directory": ".", "pattern": "*.py"})],
    ],
    responses=["Found Python files in the project. Main entry points appear to be in src/."],
  )

  agent = CoderAgent(client=client, tools=registry)
  result = agent.run("What Python files are in this project?")
  print("Agent result:")
  print(result)


if __name__ == "__main__":
  main()
