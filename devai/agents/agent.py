"""Agent loop with tool calling."""

from __future__ import annotations

from devai.core.client import LLMClient
from devai.core.models import Message, Role
from devai.memory.conversation import ConversationMemory
from devai.tools.registry import ToolRegistry


class Agent:
  """An LLM agent that can call registered tools in a loop."""

  def __init__(
    self,
    client: LLMClient,
    *,
    tools: ToolRegistry | None = None,
    system: str | None = None,
    max_steps: int = 10,
    memory: ConversationMemory | None = None,
  ) -> None:
    self.client = client
    self.tools = tools or ToolRegistry()
    self.max_steps = max_steps
    self.memory = memory or ConversationMemory(system=system)

  def run(self, user_input: str) -> str:
    """Execute the agent loop until a final text response."""
    self.memory.add(Role.USER, user_input)

    for _ in range(self.max_steps):
      messages = self.memory.messages()
      tool_defs = self.tools.definitions() if len(self.tools) else None
      result = self.client.complete(messages, tools=tool_defs)

      if result.has_tool_calls:
        assistant = Message(
          role=Role.ASSISTANT,
          content=result.content or "",
          tool_calls=result.tool_calls,
        )
        self.memory.add_message(assistant)

        for call in result.tool_calls:
          output = self.tools.run(call.name, call.arguments)
          self.memory.add_message(
            Message(
              role=Role.TOOL,
              content=output,
              tool_call_id=call.id,
              name=call.name,
            )
          )
        continue

      response = result.content or ""
      self.memory.add(Role.ASSISTANT, response)
      return response

    return "Agent reached maximum steps without a final answer."

  async def arun(self, user_input: str) -> str:
    """Async version of the agent loop."""
    self.memory.add(Role.USER, user_input)

    for _ in range(self.max_steps):
      messages = self.memory.messages()
      tool_defs = self.tools.definitions() if len(self.tools) else None
      result = await self.client.acomplete(messages, tools=tool_defs)

      if result.has_tool_calls:
        assistant = Message(
          role=Role.ASSISTANT,
          content=result.content or "",
          tool_calls=result.tool_calls,
        )
        self.memory.add_message(assistant)

        for call in result.tool_calls:
          output = self.tools.run(call.name, call.arguments)
          self.memory.add_message(
            Message(
              role=Role.TOOL,
              content=output,
              tool_call_id=call.id,
              name=call.name,
            )
          )
        continue

      response = result.content or ""
      self.memory.add(Role.ASSISTANT, response)
      return response

    return "Agent reached maximum steps without a final answer."

  def reset(self) -> None:
    """Clear conversation history."""
    self.memory.clear()

  def __repr__(self) -> str:
    return f"Agent(tools={len(self.tools)}, max_steps={self.max_steps})"
