"""DevAI command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from devai.core.client import LLMClient
from devai.core.config import DevAIConfig
from devai.prompts import (
    CODE_REVIEW,
    COMMIT_MESSAGE,
    DEBUG,
    EXPLAIN_CODE,
    REFACTOR,
    SECURITY_REVIEW,
    TEST_GEN,
)
from devai.tools import git_diff, read_file


def _get_client() -> LLMClient:
    config = DevAIConfig.from_env()
    config.validate()
    return LLMClient(config)


def cmd_review(args: argparse.Namespace) -> None:
    client = _get_client()
    code = read_file(args.file) if args.file else sys.stdin.read()
    language = args.language or Path(args.file).suffix.lstrip(".") if args.file else "unknown"
    messages = CODE_REVIEW.to_messages(code=code, language=language)
    response = client.chat(messages)
    print(response.content)


def cmd_explain(args: argparse.Namespace) -> None:
    client = _get_client()
    code = read_file(args.file) if args.file else sys.stdin.read()
    language = args.language or "python"
    messages = EXPLAIN_CODE.to_messages(code=code, language=language)
    response = client.chat(messages)
    print(response.content)


def cmd_debug(args: argparse.Namespace) -> None:
    client = _get_client()
    code_section = ""
    if args.file:
        code_section = f"Code:\n```\n{read_file(args.file)}\n```"
    messages = DEBUG.to_messages(error=args.error, code_section=code_section)
    response = client.chat(messages)
    print(response.content)


def cmd_commit(args: argparse.Namespace) -> None:
    client = _get_client()
    diff = git_diff(staged=True)
    messages = COMMIT_MESSAGE.to_messages(diff=diff)
    response = client.chat(messages)
    print(response.content)


def cmd_tests(args: argparse.Namespace) -> None:
    client = _get_client()
    code = read_file(args.file)
    messages = TEST_GEN.to_messages(code=code)
    response = client.chat(messages)
    print(response.content)


def cmd_security(args: argparse.Namespace) -> None:
    client = _get_client()
    code = read_file(args.file) if args.file else sys.stdin.read()
    messages = SECURITY_REVIEW.to_messages(code=code)
    response = client.chat(messages)
    print(response.content)


def cmd_refactor(args: argparse.Namespace) -> None:
    client = _get_client()
    code = read_file(args.file) if args.file else sys.stdin.read()
    goals = args.goals or "improve readability and maintainability"
    messages = REFACTOR.to_messages(code=code, goals=goals)
    response = client.chat(messages)
    print(response.content)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="devai",
        description="DevAI — AI tools for developers",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    review_parser = subparsers.add_parser("review", help="Review code for issues")
    review_parser.add_argument("--file", "-f", help="File to review (stdin if omitted)")
    review_parser.add_argument("--language", "-l", help="Programming language")
    review_parser.set_defaults(func=cmd_review)

    explain_parser = subparsers.add_parser("explain", help="Explain code")
    explain_parser.add_argument("--file", "-f", help="File to explain")
    explain_parser.add_argument("--language", "-l", default="python")
    explain_parser.set_defaults(func=cmd_explain)

    debug_parser = subparsers.add_parser("debug", help="Debug an error")
    debug_parser.add_argument("--error", "-e", required=True, help="Error message")
    debug_parser.add_argument("--file", "-f", help="Related source file")
    debug_parser.set_defaults(func=cmd_debug)

    commit_parser = subparsers.add_parser("commit", help="Generate commit message")
    commit_parser.set_defaults(func=cmd_commit)

    tests_parser = subparsers.add_parser("tests", help="Generate unit tests")
    tests_parser.add_argument("--file", "-f", required=True, help="Source file")
    tests_parser.set_defaults(func=cmd_tests)

    security_parser = subparsers.add_parser("security", help="Security review")
    security_parser.add_argument("--file", "-f", help="File to review")
    security_parser.set_defaults(func=cmd_security)

    refactor_parser = subparsers.add_parser("refactor", help="Refactor suggestions")
    refactor_parser.add_argument("--file", "-f", help="File to refactor")
    refactor_parser.add_argument("--goals", "-g", help="Refactoring goals")
    refactor_parser.set_defaults(func=cmd_refactor)

    args = parser.parse_args()
    try:
        args.func(args)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
