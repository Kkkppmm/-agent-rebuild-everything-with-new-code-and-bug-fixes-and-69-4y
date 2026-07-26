"""CoderAgent with built-in tools (mock client)."""

from devai.agents import CoderAgent
from devai.core.client import MockLLMClient
from devai.tools import ToolRegistry, explain_code, lint_python, count_complexity

CODE = '''
def process(items):
    result = []
    for item in items:
        if item > 0:
            result.append(item * 2)
    return result
'''

def main() -> None:
    registry = ToolRegistry()
    registry.register(explain_code)
    registry.register(lint_python)
    registry.register(count_complexity)

    client = MockLLMClient(responses=[
        "I'll analyze the code using available tools.",
        "The function filters positive items and doubles them.",
    ])
    agent = CoderAgent(client=client, tools=registry)
    result = agent.run(f"Analyze this code:\n{CODE}")
    print(result)

if __name__ == "__main__":
    main()
