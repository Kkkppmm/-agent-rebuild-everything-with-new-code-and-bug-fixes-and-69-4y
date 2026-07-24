"""Specialized coding agent with built-in developer tools."""

from __future__ import annotations

from devai.agents.agent import Agent
from devai.tools.code_tools import default_registry

CODER_SYSTEM_PROMPT = """You are an expert software engineer assistant.
You help developers write, review, debug, and refactor code.
Use available tools to analyze code when helpful.
Be precise, practical, and security-conscious."""


class CoderAgent(Agent):
    """Agent pre-configured with developer tools and a coding system prompt."""

    def __init__(self, llm, *, max_iterations: int = 10) -> None:
        super().__init__(
            llm,
            tools=default_registry,
            system_prompt=CODER_SYSTEM_PROMPT,
            max_iterations=max_iterations,
        )

    def review(self, code: str, language: str = "python") -> str:
        return self.run(f"Review this {language} code:\n```{language}\n{code}\n```")

    def explain(self, code: str, language: str = "python") -> str:
        return self.run(f"Explain this {language} code:\n```{language}\n{code}\n```")

    def debug(self, error: str, code: str = "", language: str = "python") -> str:
        return self.run(
            f"Debug this error:\n{error}\n\nCode:\n```{language}\n{code}\n```"
        )
