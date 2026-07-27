"""Agent implementations with tool calling."""

from __future__ import annotations

from typing import Any, Protocol

from devai.core.models import Message, Role
from devai.tools import ToolRegistry


class LLMProtocol(Protocol):
  def complete(self, messages: list[Message], **kwargs: Any) -> Any: ...


class Agent:
  """Base agent with tool-calling loop."""

  SYSTEM_PROMPT = "You are a helpful AI assistant for software developers."

  def __init__(
    self,
    client: LLMProtocol,
    tools: ToolRegistry | None = None,
    max_iterations: int = 10,
    system_prompt: str | None = None,
  ) -> None:
    self.client = client
    self.tools = tools or ToolRegistry()
    self.max_iterations = max_iterations
    self.system_prompt = system_prompt or self.SYSTEM_PROMPT
    self.history: list[Message] = []

  def run(self, task: str, **kwargs: Any) -> str:
    self.history = [
      Message(role=Role.SYSTEM, content=self.system_prompt),
      Message(role=Role.USER, content=task),
    ]
    tool_defs = self.tools.get_definitions() if len(self.tools._tools) > 0 else None

    for _ in range(self.max_iterations):
      result = self.client.complete(self.history, tools=tool_defs, **kwargs)

      if result.tool_calls:
        self.history.append(Message(
          role=Role.ASSISTANT,
          content=result.content or "",
          tool_calls=result.tool_calls,
        ))
        for tc in result.tool_calls:
          output = self.tools.execute(tc.name, tc.arguments)
          self.history.append(Message(
            role=Role.TOOL,
            content=output,
            tool_call_id=tc.id,
            name=tc.name,
          ))
        continue

      self.history.append(Message(role=Role.ASSISTANT, content=result.content))
      return result.content

    return "Agent reached maximum iterations without completing the task."


class CoderAgent(Agent):
  """Agent specialized for coding tasks."""

  SYSTEM_PROMPT = """You are an expert software engineer agent.
You have access to tools for reading files, searching code, linting, and analyzing complexity.
Use tools to gather context before answering. Be precise and actionable."""

  def __init__(self, client: LLMProtocol, tools: ToolRegistry | None = None, **kwargs: Any) -> None:
    super().__init__(
      client=client,
      tools=tools or ToolRegistry.default(),
      system_prompt=self.SYSTEM_PROMPT,
      **kwargs,
    )
