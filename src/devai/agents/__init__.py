"""AI agents with tool-calling support."""

from __future__ import annotations

import json
from typing import Any

from devai.core.client import LLMClient, MockLLMClient
from devai.core.models import ChatResponse, Message, Role, ToolCall
from devai.tools import ToolRegistry


class Agent:
    """Base agent that runs a tool-calling loop with an LLM."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        tools: ToolRegistry | None = None,
        system_prompt: str = "You are a helpful AI assistant for developers.",
        max_iterations: int = 10,
    ):
        self.client = client
        self.tools = tools or ToolRegistry()
        self.system_prompt = system_prompt
        self.max_iterations = max_iterations
        self.messages: list[Message] = []

    def run(self, task: str) -> str:
        """Execute a task using the agent loop."""
        self.messages = [
            Message(role=Role.SYSTEM, content=self.system_prompt),
            Message(role=Role.USER, content=task),
        ]

        tool_defs = self.tools.get_tool_definitions() if self.tools._tools else None

        for _ in range(self.max_iterations):
            response = self.client.chat(self.messages, tools=tool_defs)
            self.messages.append(Message(
                role=Role.ASSISTANT,
                content=response.content,
                tool_calls=response.tool_calls or None,
            ))

            if not response.has_tool_calls:
                return response.content

            for tc in response.tool_calls:
                result = self.tools.execute(tc.name, tc.arguments)
                self.messages.append(Message(
                    role=Role.TOOL,
                    content=result,
                    tool_call_id=tc.id,
                ))

        return self.messages[-1].content


class CoderAgent(Agent):
    """Agent specialized for programming tasks."""

    DEFAULT_SYSTEM = """You are an expert software engineer assistant. You help developers with:
- Reading and understanding code
- Writing and refactoring code
- Debugging issues
- Running linters and analysis tools

Use the available tools to gather information before answering.
Always explain your reasoning and provide clear, actionable advice."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        tools: ToolRegistry | None = None,
        max_iterations: int = 15,
    ):
        super().__init__(
            client=client,
            tools=tools,
            system_prompt=self.DEFAULT_SYSTEM,
            max_iterations=max_iterations,
        )

    def review_file(self, path: str) -> str:
        """Review a source file."""
        return self.run(f"Review the code in {path}. Read the file first, then provide a thorough code review.")

    def debug_error(self, error: str, context: str = "") -> str:
        """Debug an error message."""
        task = f"Debug this error:\n\n{error}"
        if context:
            task += f"\n\nContext:\n{context}"
        return self.run(task)

    def explain_file(self, path: str) -> str:
        """Explain what a source file does."""
        return self.run(f"Explain what the code in {path} does. Read the file first.")
