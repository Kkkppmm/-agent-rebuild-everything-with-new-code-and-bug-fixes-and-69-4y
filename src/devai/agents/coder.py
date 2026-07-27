"""Specialized coding agent."""

from __future__ import annotations

from devai.agents.agent import Agent
from devai.core.client import LLMClient, MockLLMClient
from devai.tools.registry import ToolRegistry

CODER_SYSTEM_PROMPT = """You are an expert software engineer and coding assistant.
You have access to tools for reading files, analyzing code, running lint checks,
searching codebases, and checking git diffs.

When helping with code:
1. Use tools to gather context before answering
2. Provide clear, actionable solutions
3. Explain your reasoning
4. Follow best practices for the language and framework"""


class CoderAgent(Agent):
    """An agent specialized for coding tasks with built-in developer tools."""

    def __init__(
        self,
        client: LLMClient | MockLLMClient,
        tools: ToolRegistry | None = None,
        max_iterations: int = 15,
    ):
        registry = tools or ToolRegistry()
        if len(registry) == 0:
            registry.register_builtins()
        super().__init__(
            client=client,
            tools=registry,
            system_prompt=CODER_SYSTEM_PROMPT,
            max_iterations=max_iterations,
        )

    def review(self, code: str, context: str = "") -> str:
        from devai.prompts.dev_prompts import CODE_REVIEW
        from devai.prompts.templates import PromptTemplate

        prompt = PromptTemplate(CODE_REVIEW).format(code=code, context=context)
        return self.run(prompt)

    def debug(self, error: str, code: str, context: str = "") -> str:
        from devai.prompts.dev_prompts import DEBUG
        from devai.prompts.templates import PromptTemplate

        prompt = PromptTemplate(DEBUG).format(error=error, code=code, context=context)
        return self.run(prompt)

    def refactor(self, code: str, goal: str = "readability and maintainability") -> str:
        from devai.prompts.dev_prompts import REFACTOR
        from devai.prompts.templates import PromptTemplate

        prompt = PromptTemplate(REFACTOR).format(code=code, goal=goal)
        return self.run(prompt)
