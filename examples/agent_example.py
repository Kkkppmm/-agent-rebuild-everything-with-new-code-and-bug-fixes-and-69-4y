"""Agent with tools example."""

from devai.agents import CoderAgent
from devai.core.client import MockLLMClient
from devai.tools import ToolRegistry, explain_code, lint_python

SAMPLE = """
def BadFunction(x):
    return x+1
"""


def main() -> None:
    registry = ToolRegistry()
    registry.register(explain_code)
    registry.register(lint_python)

    client = MockLLMClient(responses=["Analysis complete."])
    agent = CoderAgent(client=client, tools=registry)

    print(agent.run(f"Review this code:\n{SAMPLE}"))
    print("\nDirect tool calls:")
    print(registry.execute("explain_code", {"code": SAMPLE}))
    print(registry.execute("lint_python", {"code": SAMPLE}))


if __name__ == "__main__":
    main()
