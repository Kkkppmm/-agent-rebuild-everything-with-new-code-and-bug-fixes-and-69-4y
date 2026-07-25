"""Agent loop with tool calling support."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from devai.client import DevAI
from devai.memory import BufferMemory, Memory
from devai.tools import ToolRegistry
from devai.types import ChatResponse, Message, Role


@dataclass
class AgentResult:
  """Result from an agent run."""

  response: ChatResponse
  messages: list[Message] = field(default_factory=list)
  tool_calls_made: int = 0
  iterations: int = 0


class Agent:
  """Simple agent that can use tools in a loop until a final answer.

  Example::

      agent = Agent(client, tools=registry)
      result = await agent.run("What is 15 * 23?")
      print(result.response.content)
  """

  def __init__(
    self,
    client: DevAI,
    tools: ToolRegistry | None = None,
    memory: Memory | None = None,
    system: str | None = None,
    model: str | None = None,
    max_iterations: int = 10,
    temperature: float | None = None,
  ):
    self.client = client
    self.tools = tools
    self.memory = memory or BufferMemory(system_prompt=system)
    self.model = model
    self.max_iterations = max_iterations
    self.temperature = temperature

  async def run(self, task: str) -> AgentResult:
    """Run the agent on a task, executing tools as needed."""
    self.memory.add(Message(role=Role.USER, content=task))
    tool_calls_made = 0
    iterations = 0
    final_response: ChatResponse | None = None

    tool_defs = self.tools.list_tools() if self.tools else None

    for _ in range(self.max_iterations):
      iterations += 1
      response = await self.client.chat(
        self.memory.get_messages(),
        model=self.model,
        tools=tool_defs,
        temperature=self.temperature,
      )
      final_response = response

      if not response.tool_calls:
        self.memory.add(Message(role=Role.ASSISTANT, content=response.content))
        break

      self.memory.add(
        Message(
          role=Role.ASSISTANT,
          content=response.content,
          tool_calls=response.tool_calls,
        )
      )

      if self.tools:
        tool_messages = await self.tools.execute_all(response.tool_calls)
        tool_calls_made += len(response.tool_calls)
        for msg in tool_messages:
          self.memory.add(msg)
      else:
        break

    if final_response is None:
      final_response = ChatResponse(content="")

    return AgentResult(
      response=final_response,
      messages=self.memory.get_messages(),
      tool_calls_made=tool_calls_made,
      iterations=iterations,
    )

  async def run_with_context(self, task: str, context: dict[str, Any]) -> AgentResult:
    """Run the agent with additional context injected into the task."""
    enriched = f"Context: {context}\n\nTask: {task}"
    return await self.run(enriched)
