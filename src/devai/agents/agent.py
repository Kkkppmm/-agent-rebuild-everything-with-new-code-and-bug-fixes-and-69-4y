"""Agent framework with tool-calling loops."""

from __future__ import annotations

from devai.core.client import LLMClient, MockLLMClient
from devai.core.models import Message, Role
from devai.tools.code_utils import ToolRegistry, default_registry


class Agent:
  """Base agent with tool-calling support."""

  def __init__(
    self,
    client: LLMClient | MockLLMClient,
    tools: ToolRegistry | None = None,
    system_prompt: str = "You are a helpful coding assistant.",
    max_iterations: int = 10,
  ) -> None:
    self.client = client
    self.tools = tools or default_registry()
    self.system_prompt = system_prompt
    self.max_iterations = max_iterations
    self.messages: list[Message] = []

  def reset(self) -> None:
    self.messages.clear()

  def run(self, task: str) -> str:
    self.messages = [Message(role=Role.SYSTEM, content=self.system_prompt)]
    self.messages.append(Message(role=Role.USER, content=task))

    for _ in range(self.max_iterations):
      result = self.client.complete(
        self.messages,
        tools=self.tools.get_definitions() if len(self.tools) > 0 else None,
      )

      if result.tool_calls:
        self.messages.append(
          Message(
            role=Role.ASSISTANT,
            content=result.content or "",
            tool_calls=result.tool_calls,
          )
        )
        for tc in result.tool_calls:
          output = self.tools.execute(tc.name, tc.arguments)
          self.messages.append(
            Message(role=Role.TOOL, content=output, tool_call_id=tc.id, name=tc.name)
          )
      else:
        self.messages.append(Message(role=Role.ASSISTANT, content=result.content))
        return result.content

    return "Agent reached maximum iterations without completing the task."


class CoderAgent(Agent):
  """Agent specialized for coding tasks."""

  CODER_SYSTEM = """You are an expert software engineer agent.
You have access to tools for reading files, searching code, running git diff, and analyzing code.
Break down tasks into steps, use tools to gather context, then provide clear solutions.
Always explain your reasoning."""

  def __init__(
    self,
    client: LLMClient | MockLLMClient,
    tools: ToolRegistry | None = None,
    max_iterations: int = 15,
  ) -> None:
    super().__init__(
      client=client,
      tools=tools,
      system_prompt=self.CODER_SYSTEM,
      max_iterations=max_iterations,
    )
