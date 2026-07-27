"""Command-line interface for DevAI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from devai import CodeAssistant, DevAIConfig
from devai.agents import CoderAgent
from devai.core import MockLLMClient
from devai.tools import ToolRegistry, git_diff, list_files, read_file, search_code


def _read_input(path_or_code: str) -> str:
    p = Path(path_or_code)
    if p.exists() and p.is_file():
        return p.read_text(encoding="utf-8", errors="replace")
    return path_or_code


def cmd_review(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    code = _read_input(args.code)
    print(assistant.review(code))


def cmd_explain(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    code = _read_input(args.code)
    print(assistant.explain(code))


def cmd_debug(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    code = _read_input(args.code)
    print(assistant.debug(code, args.error))


def cmd_commit(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    diff = args.diff or git_diff()
    print(assistant.commit_message(diff))


def cmd_pr(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    diff = args.diff or git_diff()
    print(assistant.pr_description(args.title, diff))


def cmd_changelog(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    print(assistant.changelog(args.version, args.changes))


def cmd_tests(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    code = _read_input(args.code)
    print(assistant.tests(code, framework=args.framework))


def cmd_security(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    code = _read_input(args.code)
    print(assistant.security(code))


def cmd_refactor(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    code = _read_input(args.code)
    print(assistant.refactor(code, goals=args.goals))


def cmd_docstring(args: argparse.Namespace) -> None:
    assistant = _get_assistant(args)
    code = _read_input(args.code)
    print(assistant.docstring(code))


def cmd_agent(args: argparse.Namespace) -> None:
    client = MockLLMClient() if args.mock else _get_assistant(args).client
    registry = ToolRegistry()
    registry.register(read_file)
    registry.register(search_code)
    registry.register(list_files)
    registry.register(git_diff)
    agent = CoderAgent(client=client, tools=registry)
    print(agent.run(args.task))


def _get_assistant(args: argparse.Namespace) -> CodeAssistant:
    if getattr(args, "mock", False):
        return CodeAssistant(client=MockLLMClient())
    config = DevAIConfig(
        api_key=getattr(args, "api_key", None),
        model=getattr(args, "model", "gpt-4o-mini"),
    )
    return CodeAssistant(config=config)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devai",
        description="DevAI — AI tools for developers",
    )
    parser.add_argument("--mock", action="store_true", help="Use mock LLM (no API key)")
    parser.add_argument("--api-key", help="API key override")
    parser.add_argument("--model", default="gpt-4o-mini", help="Model name")

    sub = parser.add_subparsers(dest="command", help="Available commands")

    p = sub.add_parser("review", help="Review code")
    p.add_argument("code", help="Code or file path")
    p.set_defaults(func=cmd_review)

    p = sub.add_parser("explain", help="Explain code")
    p.add_argument("code", help="Code or file path")
    p.set_defaults(func=cmd_explain)

    p = sub.add_parser("debug", help="Debug code with error")
    p.add_argument("--code", required=True, help="Code or file path")
    p.add_argument("--error", required=True, help="Error message")
    p.set_defaults(func=cmd_debug)

    p = sub.add_parser("commit", help="Generate commit message")
    p.add_argument("--diff", help="Git diff (defaults to git diff)")
    p.set_defaults(func=cmd_commit)

    p = sub.add_parser("pr", help="Generate PR description")
    p.add_argument("--title", required=True, help="PR title")
    p.add_argument("--diff", help="Git diff")
    p.set_defaults(func=cmd_pr)

    p = sub.add_parser("changelog", help="Generate changelog entry")
    p.add_argument("--version", required=True)
    p.add_argument("--changes", required=True)
    p.set_defaults(func=cmd_changelog)

    p = sub.add_parser("tests", help="Generate unit tests")
    p.add_argument("code", help="Code or file path")
    p.add_argument("--framework", default="pytest")
    p.set_defaults(func=cmd_tests)

    p = sub.add_parser("security", help="Security review")
    p.add_argument("code", help="Code or file path")
    p.set_defaults(func=cmd_security)

    p = sub.add_parser("refactor", help="Refactor code")
    p.add_argument("code", help="Code or file path")
    p.add_argument("--goals", default="improve readability")
    p.set_defaults(func=cmd_refactor)

    p = sub.add_parser("docstring", help="Generate docstrings")
    p.add_argument("code", help="Code or file path")
    p.set_defaults(func=cmd_docstring)

    p = sub.add_parser("agent", help="Run coding agent")
    p.add_argument("task", help="Task description")
    p.set_defaults(func=cmd_agent)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
