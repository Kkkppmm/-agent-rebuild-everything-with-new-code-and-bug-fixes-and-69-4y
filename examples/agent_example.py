"""Agent example for DevAI."""

from devai import MockLLMClient
from devai.agents import CoderAgent
from devai.tools import ToolRegistry, read_file, search_code

registry = ToolRegistry()
registry.register(read_file)
registry.register(search_code)

agent = CoderAgent(client=MockLLMClient(), tools=registry)
response = agent.run("Read and summarize the main module")
print(response)
