"""Base agent with tool-calling loop."""

from __future__ import annotations

import json
from typing import Any

from devai.core.client import LLMClient, MockLLMClient
from devai.core.models import Message
from devai.tools.registry import ToolRegistry


class Agent:
    """An agent that can use tools in a loop until it produces a final answer."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        tools: ToolRegistry | None = None,
        system_prompt: str = "You are a helpful assistant.",
        max_iterations: int = 10,
    ):
        self.client = client
        self.tools = tools or ToolRegistry()
        self.system_prompt = system_prompt
        self.max_iterations = max_iterations

    def _build_messages(self, user_input: str, history: list[Message] | None = None) -> list[Message]:
        messages: list[Message] = [Message(role="system", content=self.system_prompt)]
        if history:
            messages.extend(history)
        messages.append(Message(role="user", content=user_input))
        return messages

    def run(
        self,
        user_input: str,
        history: list[Message] | None = None,
    ) -> str:
        """Run the agent loop until a final text response is produced."""
        messages = self._build_messages(user_input, history)
        tool_defs = self.tools.get_definitions() if len(self.tools) > 0 else None

        for _ in range(self.max_iterations):
            response = self.client.chat(
                messages,
                tools=tool_defs,
            )

            if not response.has_tool_calls:
                return response.content or ""

            assistant_msg = Message(
                role="assistant",
                content=response.content,
                tool_calls=response.tool_calls,
            )
            messages.append(assistant_msg)

            for tc in response.tool_calls:
                result = self.tools.execute(tc.name, tc.arguments)
                messages.append(
                    Message(role="tool", content=result, tool_call_id=tc.id, name=tc.name)
                )

        return "Max iterations reached without a final answer."

    def run_with_steps(
        self,
        user_input: str,
        history: list[Message] | None = None,
    ) -> dict[str, Any]:
        """Run the agent and return intermediate steps."""
        messages = self._build_messages(user_input, history)
        tool_defs = self.tools.get_definitions() if len(self.tools) > 0 else None
        steps: list[dict[str, Any]] = []

        for i in range(self.max_iterations):
            response = self.client.chat(messages, tools=tool_defs)
            step: dict[str, Any] = {"iteration": i, "content": response.content}

            if not response.has_tool_calls:
                step["final"] = True
                steps.append(step)
                return {"answer": response.content or "", "steps": steps}

            step["tool_calls"] = [
                {"name": tc.name, "arguments": tc.arguments} for tc in response.tool_calls
            ]
            steps.append(step)

            messages.append(
                Message(role="assistant", content=response.content, tool_calls=response.tool_calls)
            )

            for tc in response.tool_calls:
                result = self.tools.execute(tc.name, tc.arguments)
                steps[-1].setdefault("tool_results", []).append(
                    {"name": tc.name, "result": result}
                )
                messages.append(
                    Message(role="tool", content=result, tool_call_id=tc.id, name=tc.name)
                )

        return {"answer": "Max iterations reached.", "steps": steps}
