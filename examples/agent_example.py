"""Agent example with tool calling."""

from devai import DevAIConfig
from devai.agents import CoderAgent
from devai.tools import ToolRegistry, default_tools

config = DevAIConfig.mock()
registry = ToolRegistry()
for tool in default_tools():
    registry.register(tool)

agent = CoderAgent(config=config, tools=registry)

result = agent.run("List all Python files in the src directory")
print(result)
