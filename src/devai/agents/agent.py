"""Agent framework with tool-calling loop."""

from __future__ import annotations

from typing import Any

from devai.core.client import LLMClient, MockLLMClient
from devai.core.models import Message, Role, ToolCall
from devai.tools.code import ToolRegistry, create_default_registry


class Agent:
    """Base agent that runs a tool-calling loop with an LLM."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        tools: ToolRegistry | None = None,
        system_prompt: str = "You are a helpful AI assistant for developers.",
        max_iterations: int = 10,
    ) -> None:
        self.client = client
        self.tools = tools or create_default_registry()
        self.system_prompt = system_prompt
        self.max_iterations = max_iterations
        self.messages: list[Message] = [
            Message(role=Role.SYSTEM, content=system_prompt)
        ]

    def reset(self) -> None:
        self.messages = [Message(role=Role.SYSTEM, content=self.system_prompt)]

    def _execute_tool_calls(self, tool_calls: list[ToolCall]) -> list[Message]:
        results: list[Message] = []
        for tc in tool_calls:
            output = self.tools.execute(tc.name, tc.arguments)
            results.append(
                Message(
                    role=Role.TOOL,
                    content=output,
                    tool_call_id=tc.id,
                    name=tc.name,
                )
            )
        return results

    def run(self, user_input: str) -> str:
        """Run the agent loop until a final text response is produced."""
        self.messages.append(Message(role=Role.USER, content=user_input))

        for _ in range(self.max_iterations):
            response = self.client.chat(
                self.messages,
                tools=self.tools.list_tools(),
            )

            if response.tool_calls:
                self.messages.append(
                    Message(
                        role=Role.ASSISTANT,
                        content=response.content or "",
                        tool_calls=response.tool_calls,
                    )
                )
                self.messages.extend(self._execute_tool_calls(response.tool_calls))
            else:
                self.messages.append(
                    Message(role=Role.ASSISTANT, content=response.content)
                )
                return response.content

        return "Max iterations reached without a final response."

    async def arun(self, user_input: str) -> str:
        """Async version of run."""
        self.messages.append(Message(role=Role.USER, content=user_input))

        for _ in range(self.max_iterations):
            response = await self.client.achat(
                self.messages,
                tools=self.tools.list_tools(),
            )

            if response.tool_calls:
                self.messages.append(
                    Message(
                        role=Role.ASSISTANT,
                        content=response.content or "",
                        tool_calls=response.tool_calls,
                    )
                )
                self.messages.extend(self._execute_tool_calls(response.tool_calls))
            else:
                self.messages.append(
                    Message(role=Role.ASSISTANT, content=response.content)
                )
                return response.content

        return "Max iterations reached without a final response."


class CoderAgent(Agent):
    """Agent specialized for coding tasks."""

    CODER_SYSTEM = (
        "You are an expert software engineer. You write clean, well-tested code. "
        "Use the available tools to analyze code, read files, and check complexity. "
        "Always explain your reasoning before making changes."
    )

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        tools: ToolRegistry | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            client=client,
            tools=tools,
            system_prompt=self.CODER_SYSTEM,
            **kwargs,
        )

    def review(self, code: str, language: str = "python") -> str:
        return self.run(f"Review this {language} code:\n```\n{code}\n```")

    def debug(self, code: str, error: str) -> str:
        return self.run(
            f"Debug this error:\n{error}\n\nCode:\n```\n{code}\n```"
        )

    def refactor(self, code: str, goal: str = "readability") -> str:
        return self.run(
            f"Refactor this code to improve {goal}:\n```\n{code}\n```"
        )
