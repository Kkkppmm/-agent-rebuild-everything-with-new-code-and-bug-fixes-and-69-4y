"""Coder agent with pre-registered developer tools."""

from devai.agents.agent import Agent
from devai.tools.registry import ToolRegistry
from devai.tools.code_tools import (
    explain_code,
    lint_python,
    search_code,
    git_diff,
    read_file,
    count_complexity,
)

CODER_SYSTEM_PROMPT = """You are an expert software engineer assistant. You help developers with:
- Code review and debugging
- Writing and refactoring code
- Searching and analyzing codebases
- Git operations and commit messages

Use the available tools to gather context before answering.
Be precise, practical, and provide code examples when helpful."""


def _build_coder_registry() -> ToolRegistry:
    registry = ToolRegistry()

    registry.register(
        "explain_code",
        explain_code,
        "Analyze code structure and return a summary of classes, functions, and imports.",
        {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Source code to analyze"},
                "language": {"type": "string", "description": "Programming language", "default": "python"},
            },
            "required": ["code"],
        },
    )

    registry.register(
        "lint_python",
        lint_python,
        "Run basic lint checks on Python code.",
        {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Python source code"},
            },
            "required": ["code"],
        },
    )

    registry.register(
        "search_code",
        search_code,
        "Search for a regex pattern in files under a directory.",
        {
            "type": "object",
            "properties": {
                "directory": {"type": "string", "description": "Root directory to search"},
                "pattern": {"type": "string", "description": "Regex pattern"},
                "file_pattern": {"type": "string", "description": "Glob for files", "default": "*.py"},
            },
            "required": ["directory", "pattern"],
        },
    )

    registry.register(
        "git_diff",
        git_diff,
        "Get git diff for a path.",
        {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to diff", "default": "."},
                "staged": {"type": "boolean", "description": "Show staged changes", "default": False},
            },
        },
    )

    registry.register(
        "read_file",
        read_file,
        "Read contents of a file.",
        {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path"},
                "max_lines": {"type": "integer", "description": "Max lines to read", "default": 500},
            },
            "required": ["path"],
        },
    )

    registry.register(
        "count_complexity",
        count_complexity,
        "Calculate cyclomatic complexity for Python functions.",
        {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Python source code"},
            },
            "required": ["code"],
        },
    )

    return registry


class CoderAgent(Agent):
    """Agent pre-configured with developer tooling."""

    def __init__(self, client, tools: ToolRegistry | None = None, **kwargs) -> None:
        super().__init__(
            client=client,
            system_prompt=CODER_SYSTEM_PROMPT,
            tools=tools or _build_coder_registry(),
            **kwargs,
        )
