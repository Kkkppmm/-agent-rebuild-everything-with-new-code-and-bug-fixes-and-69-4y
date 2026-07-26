"""Coder-focused agent with developer tools."""

from __future__ import annotations

from devai.agents.agent import Agent, LLMProtocol
from devai.tools.registry import ToolRegistry, default_registry

CODER_SYSTEM_PROMPT = """You are an expert software engineer and coding assistant.
You help developers write, debug, review, and refactor code.
Use available tools to inspect code, run lint checks, and search the codebase.
Be precise, practical, and provide working code examples."""


class CoderAgent(Agent):
    """Agent pre-configured with developer tools and coding expertise."""

    def __init__(
        self,
        llm: LLMProtocol,
        tools: ToolRegistry | None = None,
        system_prompt: str = CODER_SYSTEM_PROMPT,
        max_iterations: int = 10,
    ) -> None:
        super().__init__(
            llm=llm,
            tools=tools or default_registry(),
            system_prompt=system_prompt,
            max_iterations=max_iterations,
        )

    def review(self, code: str, language: str = "python") -> str:
        return self.run(f"Review this {language} code:\n```{language}\n{code}\n```")

    def debug(self, code: str, error: str, language: str = "python") -> str:
        return self.run(
            f"Debug this error in {language} code:\n\nError: {error}\n\n"
            f"```{language}\n{code}\n```"
        )

    def refactor(self, code: str, language: str = "python") -> str:
        return self.run(f"Refactor this {language} code:\n```{language}\n{code}\n```")
