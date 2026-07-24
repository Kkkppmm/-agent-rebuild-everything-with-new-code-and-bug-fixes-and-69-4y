"""Agent implementations for DevAI."""

from typing import Any

from devai.core.client import LLMClient, MockLLMClient
from devai.core.models import Message, ToolCall
from devai.tools.registry import ToolRegistry


class Agent:
    """Base agent that runs tasks with an LLM client."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        system_prompt: str = "You are a helpful AI assistant for developers.",
        max_iterations: int = 10,
    ) -> None:
        self.client = client
        self.system_prompt = system_prompt
        self.max_iterations = max_iterations
        self.history: list[Message] = []

    def run(self, task: str) -> str:
        self.history.append(Message(role="user", content=task))
        response = self.client.complete(self.history, system=self.system_prompt)
        self.history.append(Message(role="assistant", content=response.content))
        return response.content

    def reset(self) -> None:
        self.history.clear()


class CoderAgent(Agent):
    """Agent with tool-calling capabilities for coding tasks."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        tools: ToolRegistry | None = None,
        system_prompt: str = (
            "You are an expert software engineer. Use available tools to "
            "analyze code, search files, and solve programming problems."
        ),
        max_iterations: int = 10,
    ) -> None:
        super().__init__(client, system_prompt, max_iterations)
        self.tools = tools or ToolRegistry()

    def run(self, task: str) -> str:
        self.history.append(Message(role="user", content=task))
        tool_defs = self.tools.list_tools()

        for _ in range(self.max_iterations):
            response = self.client.complete(
                self.history,
                system=self.system_prompt,
                tools=tool_defs if tool_defs else None,
            )

            if not response.has_tool_calls:
                self.history.append(Message(role="assistant", content=response.content))
                return response.content

            self.history.append(
                Message(
                    role="assistant",
                    content=response.content or "",
                    tool_calls=response.tool_calls,
                )
            )

            for tc in response.tool_calls or []:
                result = self.tools.execute(tc.name, tc.arguments)
                self.history.append(
                    Message(
                        role="tool",
                        content=str(result),
                        tool_call_id=tc.id,
                    )
                )

        return "Max iterations reached without a final response."

    def run_with_tools(self, task: str, tool_calls: list[ToolCall]) -> str:
        """Run with pre-defined tool calls (useful for testing)."""
        self.history.append(Message(role="user", content=task))
        for tc in tool_calls:
            result = self.tools.execute(tc.name, tc.arguments)
            self.history.append(
                Message(role="tool", content=str(result), tool_call_id=tc.id)
            )
        response = self.client.complete(self.history, system=self.system_prompt)
        self.history.append(Message(role="assistant", content=response.content))
        return response.content
