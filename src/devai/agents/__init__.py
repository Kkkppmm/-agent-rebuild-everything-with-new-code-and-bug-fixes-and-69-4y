"""Agent framework with tool-calling loops."""

from __future__ import annotations

from typing import Any

from devai.core.client import LLMClient, MockLLMClient
from devai.core.models import Role
from devai.memory import ConversationMemory
from devai.tools import ToolRegistry


class Agent:
    """Base agent with conversation memory and tool execution."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        tools: ToolRegistry | None = None,
        system_prompt: str = "You are a helpful coding assistant.",
        max_iterations: int = 10,
    ) -> None:
        self.client = client
        self.tools = tools or ToolRegistry()
        self.system_prompt = system_prompt
        self.max_iterations = max_iterations
        self.memory = ConversationMemory()

    def run(self, task: str) -> str:
        self.memory.add(Role.SYSTEM, self.system_prompt)
        self.memory.add(Role.USER, task)

        for _ in range(self.max_iterations):
            messages = self.memory.get_messages()
            tool_defs = self.tools.get_definitions() if self.tools._tools else None
            response = self.client.complete(messages, tools=tool_defs)
            self.memory.add(Role.ASSISTANT, response.content, tool_calls=response.tool_calls)

            if not response.tool_calls:
                return response.content

            for tc in response.tool_calls:
                result = self.tools.execute(tc.name, tc.arguments)
                self.memory.add(Role.TOOL, result, tool_call_id=tc.id, name=tc.name)

        return self.memory.get_messages()[-1].content


class CoderAgent(Agent):
    """Agent specialized for coding tasks."""

    SYSTEM_PROMPT = (
        "You are an expert software engineer. You have access to tools for reading files, "
        "searching code, running lint checks, and analyzing complexity. "
        "Use tools when needed, then provide clear, actionable answers."
    )

    def __init__(self, client: LLMClient | MockLLMClient, tools: ToolRegistry | None = None, **kwargs: Any) -> None:
        if tools is None:
            from devai.tools import (
                count_complexity,
                explain_code,
                lint_python,
                list_directory,
                read_file,
                search_code,
            )

            tools = ToolRegistry()
            for fn in (read_file, search_code, lint_python, count_complexity, explain_code, list_directory):
                tools.register(fn)
        super().__init__(client, tools=tools, system_prompt=self.SYSTEM_PROMPT, **kwargs)
