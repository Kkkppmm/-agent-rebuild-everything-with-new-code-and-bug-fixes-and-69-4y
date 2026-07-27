"""Command-line interface for DevAI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from devai import CodeAssistant, DevAIConfig
from devai.agents import CoderAgent
from devai.tools import ToolRegistry, default_tools
from devai.tools.code_utils import git_diff


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="devai",
        description="DevAI — AI tools for developers",
    )
    parser.add_argument("--mock", action="store_true", help="Use mock LLM (no API key)")
    parser.add_argument("--model", default=None, help="LLM model name")
    sub = parser.add_subparsers(dest="command", required=True)

    review_p = sub.add_parser("review", help="Review code")
    review_p.add_argument("file", nargs="?", help="File to review")
    review_p.add_argument("--code", default=None, help="Inline code string")

    explain_p = sub.add_parser("explain", help="Explain code")
    explain_p.add_argument("code", help="Code to explain")

    debug_p = sub.add_parser("debug", help="Debug code with an error")
    debug_p.add_argument("--code", required=True, help="Code with the bug")
    debug_p.add_argument("--error", required=True, help="Error message")

    commit_p = sub.add_parser("commit", help="Generate commit message from diff")
    commit_p.add_argument("--diff", default=None, help="Diff file path")
    commit_p.add_argument("--staged", action="store_true", help="Use staged git diff")

    tests_p = sub.add_parser("tests", help="Generate unit tests")
    tests_p.add_argument("file", nargs="?", help="File to test")

    security_p = sub.add_parser("security", help="Security review")
    security_p.add_argument("file", nargs="?", help="File to review")

    refactor_p = sub.add_parser("refactor", help="Refactor code")
    refactor_p.add_argument("file", nargs="?", help="File to refactor")

    agent_p = sub.add_parser("agent", help="Run coding agent")
    agent_p.add_argument("task", help="Task for the agent")

    args = parser.parse_args(argv)
    config = DevAIConfig.mock() if args.mock else DevAIConfig.from_env()
    if args.model:
        config.model = args.model
    assistant = CodeAssistant(config=config)

    if args.command == "review":
        code = _read_code(args.file, args.code)
        print(assistant.review(code))
    elif args.command == "explain":
        print(assistant.explain(args.code))
    elif args.command == "debug":
        print(assistant.debug(args.code, args.error))
    elif args.command == "commit":
        diff = Path(args.diff).read_text() if args.diff else git_diff(staged=args.staged)
        print(assistant.commit_message(diff))
    elif args.command == "tests":
        code = _read_code(args.file, None)
        print(assistant.generate_tests(code))
    elif args.command == "security":
        code = _read_code(args.file, None)
        print(assistant.security(code))
    elif args.command == "refactor":
        code = _read_code(args.file, None)
        print(assistant.refactor(code))
    elif args.command == "agent":
        registry = ToolRegistry()
        for tool in default_tools():
            registry.register(tool)
        agent = CoderAgent(config=config, tools=registry)
        print(agent.run(args.task))

    return 0


def _read_code(file_path: str | None, inline: str | None) -> str:
    if inline:
        return inline
    if file_path:
        return Path(file_path).read_text(encoding="utf-8")
    return sys.stdin.read()


if __name__ == "__main__":
    raise SystemExit(main())
