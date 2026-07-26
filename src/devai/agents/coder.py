"""Specialized coding agent."""

from __future__ import annotations

from devai.agents.agent import Agent
from devai.core.client import LLMClient, MockLLMClient
from devai.tools.code import registry as code_registry

CODER_SYSTEM_PROMPT = """You are an expert software engineer and coding assistant.
You help developers write, debug, review, and refactor code.
Use available tools to analyze code when helpful.
Be precise, practical, and provide working solutions."""


class CoderAgent(Agent):
    """Agent specialized for coding tasks with built-in code tools."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        *,
        max_iterations: int = 10,
    ) -> None:
        super().__init__(
            client=client,
            tools=code_registry,
            system_prompt=CODER_SYSTEM_PROMPT,
            max_iterations=max_iterations,
        )

    def review(self, code: str, language: str = "python") -> str:
        return self.run(f"Review this {language} code:\n```{language}\n{code}\n```")

    def explain(self, code: str, language: str = "python") -> str:
        return self.run(f"Explain this {language} code:\n```{language}\n{code}\n```")

    def debug(self, code: str, error: str, language: str = "python") -> str:
        return self.run(
            f"Debug this {language} error:\nError: {error}\n\n"
            f"```{language}\n{code}\n```"
        )

    def refactor(self, code: str, goal: str = "readability", language: str = "python") -> str:
        return self.run(
            f"Refactor this {language} code for {goal}:\n```{language}\n{code}\n```"
        )
