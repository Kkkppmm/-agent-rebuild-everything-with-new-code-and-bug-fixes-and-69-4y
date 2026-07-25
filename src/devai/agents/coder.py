"""Coder agent specialized for programming tasks."""

from __future__ import annotations

from devai.agents.agent import Agent
from devai.core.client import LLMClient
from devai.core.config import DevAIConfig
from devai.memory.conversation import ConversationMemory
from devai.tools.code_utils import create_default_registry
from devai.tools.registry import ToolRegistry

CODER_SYSTEM_PROMPT = """You are an expert software engineer and coding assistant.

You have access to tools for reading files, searching code, running git diffs,
linting Python code, and analyzing complexity. Use them to understand the
codebase before making suggestions.

When writing code:
- Write clean, idiomatic, well-tested code
- Follow the project's existing conventions
- Explain your reasoning briefly
- Prefer minimal, focused changes"""


class CoderAgent(Agent):
    """An agent pre-configured for developer workflows."""

    def __init__(
        self,
        client: LLMClient | None = None,
        config: DevAIConfig | None = None,
        tools: ToolRegistry | None = None,
        system_prompt: str = CODER_SYSTEM_PROMPT,
        max_iterations: int = 15,
        memory: ConversationMemory | None = None,
        working_directory: str | None = None,
    ):
        super().__init__(
            client=client,
            config=config,
            tools=tools or create_default_registry(),
            system_prompt=system_prompt,
            max_iterations=max_iterations,
            memory=memory,
        )
        self.working_directory = working_directory

    async def review(self, code: str, language: str = "python") -> str:
        from devai.prompts.dev_prompts import CODE_REVIEW

        prompt = CODE_REVIEW.format(code=code, language=language)
        return await self.run(prompt)

    async def debug(
        self,
        code: str,
        error: str,
        language: str = "python",
        context: str = "",
    ) -> str:
        from devai.prompts.dev_prompts import DEBUG

        prompt = DEBUG.format(
            code=code, error=error, language=language, context=context
        )
        return await self.run(prompt)

    async def refactor(
        self, code: str, goal: str = "readability and maintainability", language: str = "python"
    ) -> str:
        from devai.prompts.dev_prompts import REFACTOR

        prompt = REFACTOR.format(code=code, goal=goal, language=language)
        return await self.run(prompt)
