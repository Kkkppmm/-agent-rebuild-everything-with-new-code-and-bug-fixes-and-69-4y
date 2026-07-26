"""Coder agent with built-in code tools."""

from __future__ import annotations

from typing import Any

from devai.agents.agent import Agent
from devai.tools.code import register_code_tools
from devai.tools.registry import ToolRegistry

CODER_SYSTEM_PROMPT = """You are an expert software engineer and coding assistant.
You help developers write, debug, review, and understand code.
When you need to inspect code or files, use the available tools.
Be concise, accurate, and provide working code examples."""


class CoderAgent(Agent):
    """Agent specialized for coding tasks with built-in code tools."""

    def __init__(self, llm: Any, extra_tools: ToolRegistry | None = None):
        registry = ToolRegistry()
        register_code_tools(registry)
        if extra_tools:
            for name in extra_tools._tools:
                registry.register(
                    name,
                    extra_tools._tools[name],
                    extra_tools._schemas[name].description,
                    extra_tools._schemas[name].parameters,
                )
        super().__init__(
            llm=llm,
            system_prompt=CODER_SYSTEM_PROMPT,
            tools=registry,
            max_iterations=15,
        )
