"""Tool calling example."""

from devai import DevAI, ToolRegistry

registry = ToolRegistry()


@registry.register(description="Multiply two integers")
def multiply(a: int, b: int) -> int:
    return a * b


@registry.register(description="Format a greeting")
def greet(name: str) -> str:
    return f"Hello, {name}!"


ai = DevAI.mock()
ai.tools = registry

# Direct tool execution
print(registry.execute("multiply", {"a": 6, "b": 7}))

# Agent loop with tool calls (mock triggers weather tool)
weather_registry = ToolRegistry()


@weather_registry.register(description="Get weather for a city")
def get_weather(city: str) -> str:
    return f"72°F and sunny in {city}"


ai.tools = weather_registry
response = ai.run_with_tools("What's the weather today?")
print("Agent response:", response.content or "(tool call handled)")
