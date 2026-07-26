"""Coder agent specialized for programming tasks."""

from __future__ import annotations

from dataclasses import dataclass, field

from devai.agents.agent import Agent
from devai.core.client import LLMClient
from devai.tools.code_utils import create_code_tools
from devai.tools.registry import ToolRegistry

CODER_SYSTEM_PROMPT = """You are an expert software engineer and coding assistant.
You help developers write, debug, review, and refactor code.
Use the available tools to analyze code, read files, and gather context.
Always provide clear explanations and working code examples."""


@dataclass
class CoderAgent(Agent):
    """An agent specialized for coding tasks with built-in code tools."""

    client: LLMClient
    tools: ToolRegistry = field(default_factory=create_code_tools)
    system_prompt: str = CODER_SYSTEM_PROMPT
    max_iterations: int = 15

    def review(self, code: str, language: str = "python") -> str:
        return self.run(f"Review this {language} code:\n```{language}\n{code}\n```")

    def debug(self, code: str, error: str) -> str:
        return self.run(f"Debug this error:\n{error}\n\nCode:\n```\n{code}\n```")

    def explain(self, code: str, language: str = "python") -> str:
        return self.run(f"Explain this {language} code:\n```{language}\n{code}\n```")

    def refactor(self, code: str, goals: str = "readability and performance") -> str:
        return self.run(f"Refactor this code for {goals}:\n```\n{code}\n```")
