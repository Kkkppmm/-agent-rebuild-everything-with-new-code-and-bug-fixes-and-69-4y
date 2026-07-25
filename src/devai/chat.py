"""Chat session with memory for multi-turn conversations."""

from __future__ import annotations

from typing import AsyncIterator

from devai.client import DevAI
from devai.memory import BufferMemory, Memory
from devai.tools import ToolRegistry
from devai.types import ChatResponse, Message, Role, StreamChunk, ToolDefinition


class ChatSession:
  """Stateful chat session with conversation memory.

  Example::

      session = ChatSession(client, system="You are a helpful assistant.")
      reply = await session.send("What is Python?")
      follow_up = await session.send("Give me an example.")
  """

  def __init__(
    self,
    client: DevAI,
    memory: Memory | None = None,
    system: str | None = None,
    tools: ToolRegistry | None = None,
    model: str | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
    auto_execute_tools: bool = True,
  ):
    self.client = client
    self.memory = memory or BufferMemory(system_prompt=system)
    self.tools = tools
    self.model = model
    self.temperature = temperature
    self.max_tokens = max_tokens
    self.auto_execute_tools = auto_execute_tools

  @property
  def tool_definitions(self) -> list[ToolDefinition] | None:
    if self.tools:
      return self.tools.list_tools()
    return None

  async def send(self, message: str) -> ChatResponse:
    """Send a user message and return the assistant response."""
    self.memory.add(Message(role=Role.USER, content=message))
    response = await self.client.chat(
      self.memory.get_messages(),
      model=self.model,
      tools=self.tool_definitions,
      temperature=self.temperature,
      max_tokens=self.max_tokens,
    )
    await self._record_response(response)
    return response

  async def stream(self, message: str) -> AsyncIterator[StreamChunk]:
    """Stream a response for a user message."""
    self.memory.add(Message(role=Role.USER, content=message))
    full_content = ""
    async for chunk in self.client.stream(
      self.memory.get_messages(),
      model=self.model,
      tools=self.tool_definitions,
      temperature=self.temperature,
      max_tokens=self.max_tokens,
    ):
      if chunk.content:
        full_content += chunk.content
      yield chunk
      if chunk.done:
        break
    self.memory.add(Message(role=Role.ASSISTANT, content=full_content))

  async def _record_response(self, response: ChatResponse) -> None:
    if response.tool_calls:
      self.memory.add(
        Message(
          role=Role.ASSISTANT,
          content=response.content,
          tool_calls=response.tool_calls,
        )
      )
      if self.tools and self.auto_execute_tools:
        tool_messages = await self.tools.execute_all(response.tool_calls)
        for msg in tool_messages:
          self.memory.add(msg)
    else:
      self.memory.add(Message(role=Role.ASSISTANT, content=response.content))

  def history(self) -> list[Message]:
    return self.memory.get_messages()

  def clear(self) -> None:
    self.memory.clear()
