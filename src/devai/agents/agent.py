"""Base agent for DevAI."""

from __future__ import annotations

from typing import Any

from devai.core.models import Message
from devai.memory.conversation import ConversationMemory
from devai.tools.registry import ToolRegistry


class Agent:
    """LLM agent with conversation memory and optional tools."""

    def __init__(
        self,
        llm: Any,
        system_prompt: str = "You are a helpful programming assistant.",
        tools: ToolRegistry | None = None,
        max_iterations: int = 10,
        memory: ConversationMemory | None = None,
    ):
        self.llm = llm
        self.system_prompt = system_prompt
        self.tools = tools
        self.max_iterations = max_iterations
        self.memory = memory or ConversationMemory(system_prompt=system_prompt)

    def run(self, user_input: str) -> str:
        self.memory.add_user(user_input)

        for _ in range(self.max_iterations):
            messages = self.memory.get_messages()
            tool_schemas = self.tools.get_schemas() if self.tools else None
            response = self.llm.chat(messages, tools=tool_schemas)

            if response.has_tool_calls and self.tools:
                self.memory.add(Message.assistant(tool_calls=response.tool_calls))
                for tc in response.tool_calls:
                    result = self.tools.execute(tc.name, tc.arguments)
                    self.memory.add(
                        Message.tool(result, tool_call_id=tc.id, name=tc.name)
                    )
                continue

            content = response.content or ""
            self.memory.add_assistant(content)
            return content

        return "Max iterations reached without a final response."

    def reset(self) -> None:
        self.memory.clear()
