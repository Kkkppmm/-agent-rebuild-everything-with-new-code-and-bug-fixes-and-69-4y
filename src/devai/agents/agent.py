"""Base agent with tool-calling loop."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from devai.core.client import LLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message
from devai.memory.conversation import ConversationMemory
from devai.tools.registry import ToolRegistry


@dataclass
class AgentResult:
  """Result of an agent run."""

  content: str
  messages: list[Message] = field(default_factory=list)
  tool_calls_made: int = 0
  iterations: int = 0


class Agent:
  """LLM agent that can use tools in a ReAct-style loop."""

  def __init__(
    self,
    client: LLMClient | None = None,
    tools: ToolRegistry | None = None,
    *,
    system_prompt: str = "You are a helpful AI assistant.",
    max_iterations: int = 10,
    memory: ConversationMemory | None = None,
  ) -> None:
    self.client = client or LLMClient()
    self.tools = tools or ToolRegistry()
    self.system_prompt = system_prompt
    self.max_iterations = max_iterations
    self.memory = memory or ConversationMemory()

  def run(self, user_input: str) -> AgentResult:
    """Process user input, optionally calling tools, and return the final response."""
    self.memory.add_user(user_input)
    tool_calls_made = 0

    for iteration in range(1, self.max_iterations + 1):
      messages = self._build_messages()
      tool_defs = self.tools.get_definitions() if len(self.tools) > 0 else None
      response = self.client.chat(messages, tools=tool_defs)

      if not response.has_tool_calls:
        self.memory.add_assistant(response.content)
        return AgentResult(
          content=response.content,
          messages=self.memory.get_messages(),
          tool_calls_made=tool_calls_made,
          iterations=iteration,
        )

      self.memory.add(Message.assistant(response.content, tool_calls=response.tool_calls))

      for tc in response.tool_calls:
        tool_calls_made += 1
        result = self.tools.execute(tc.name, tc.arguments)
        self.memory.add(Message.tool(result, tool_call_id=tc.id))

    return AgentResult(
      content="Max iterations reached without a final response.",
      messages=self.memory.get_messages(),
      tool_calls_made=tool_calls_made,
      iterations=self.max_iterations,
    )

  async def arun(self, user_input: str) -> AgentResult:
    """Async version of run."""
    self.memory.add_user(user_input)
    tool_calls_made = 0

    for iteration in range(1, self.max_iterations + 1):
      messages = self._build_messages()
      tool_defs = self.tools.get_definitions() if len(self.tools) > 0 else None
      response = await self.client.achat(messages, tools=tool_defs)

      if not response.has_tool_calls:
        self.memory.add_assistant(response.content)
        return AgentResult(
          content=response.content,
          messages=self.memory.get_messages(),
          tool_calls_made=tool_calls_made,
          iterations=iteration,
        )

      self.memory.add(Message.assistant(response.content, tool_calls=response.tool_calls))

      for tc in response.tool_calls:
        tool_calls_made += 1
        result = self.tools.execute(tc.name, tc.arguments)
        self.memory.add(Message.tool(result, tool_call_id=tc.id))

    return AgentResult(
      content="Max iterations reached without a final response.",
      messages=self.memory.get_messages(),
      tool_calls_made=tool_calls_made,
      iterations=self.max_iterations,
    )

  def reset(self) -> None:
    self.memory.clear()

  def _build_messages(self) -> list[Message]:
    msgs = [Message.system(self.system_prompt)]
    msgs.extend(self.memory.get_messages())
    return msgs

  @classmethod
  def from_config(cls, config: DevAIConfig, **kwargs: Any) -> Agent:
    return cls(client=LLMClient(config), **kwargs)
