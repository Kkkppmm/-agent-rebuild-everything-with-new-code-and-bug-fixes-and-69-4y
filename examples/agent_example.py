"""Agent example for DevAI."""

from devai.agents import CoderAgent
from devai.core import MockLLMClient
from devai.tools import ToolRegistry, list_files, read_file, search_code

client = MockLLMClient(
    responses=[
        "I'll search the codebase for TODO comments.",
        "Found 3 TODO comments in the project. They are in utils.py, main.py, and config.py.",
    ]
)

registry = ToolRegistry()
registry.register(read_file)
registry.register(search_code)
registry.register(list_files)

agent = CoderAgent(client=client, tools=registry)

result = agent.run("Find all TODO comments in the codebase")
print("Agent result:", result)
print(f"LLM calls made: {len(client.call_history)}")
