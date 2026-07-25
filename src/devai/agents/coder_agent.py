"""Coder agent specialized for software development tasks."""

from __future__ import annotations

from devai.agents.agent import Agent
from devai.core.client import LLMClient
from devai.tools.code_tools import create_dev_tools
from devai.tools.registry import ToolRegistry

CODER_SYSTEM_PROMPT = """You are an expert software engineer and coding assistant.

You have access to tools for reading files, searching code, running git diff,
analyzing Python code, and more. Use them when needed to understand the codebase
before making recommendations.

When writing code:
- Write clean, idiomatic, well-tested code
- Follow the project's existing conventions
- Explain your reasoning briefly
- Prefer minimal, focused changes"""


class CoderAgent(Agent):
  """Agent pre-configured for developer workflows with built-in dev tools."""

  def __init__(
    self,
    client: LLMClient | None = None,
    tools: ToolRegistry | None = None,
    *,
    project_root: str = ".",
    max_iterations: int = 15,
  ) -> None:
    dev_tools = tools or create_dev_tools(project_root)
    super().__init__(
      client=client,
      tools=dev_tools,
      system_prompt=CODER_SYSTEM_PROMPT,
      max_iterations=max_iterations,
    )
    self.project_root = project_root
