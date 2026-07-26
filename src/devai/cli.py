"""DevAI command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from devai import (
    CODE_REVIEW,
    COMMIT_MESSAGE,
    DEBUG,
    EXPLAIN_CODE,
    GENERATE_TESTS,
    REFACTOR,
    SECURITY_REVIEW,
    DevAIConfig,
    LLMClient,
    MockLLMClient,
    PromptTemplate,
)


def _get_client(use_mock: bool = False) -> LLMClient | MockLLMClient:
    if use_mock:
        return MockLLMClient()
    config = DevAIConfig()
    try:
        config.validate()
    except Exception:
        print("Warning: No API key found. Using mock client. Set DEVAI_API_KEY to use a real LLM.", file=sys.stderr)
        return MockLLMClient()
    return LLMClient(config)


def _read_input(path: str | None, stdin_default: str = "") -> str:
    if path:
        return Path(path).read_text(encoding="utf-8")
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return stdin_default


def cmd_review(args: argparse.Namespace) -> None:
    code = _read_input(args.file)
    prompt = PromptTemplate(CODE_REVIEW).format(code=code, context=args.context or "")
    client = _get_client(args.mock)
    response = client.chat([{"role": "user", "content": prompt}])
    print(response.content)


def cmd_explain(args: argparse.Namespace) -> None:
    code = args.code or _read_input(args.file)
    prompt = PromptTemplate(EXPLAIN_CODE).format(code=code, language=args.language)
    client = _get_client(args.mock)
    response = client.chat([{"role": "user", "content": prompt}])
    print(response.content)


def cmd_debug(args: argparse.Namespace) -> None:
    code = _read_input(args.file)
    prompt = PromptTemplate(DEBUG).format(error=args.error, code=code, context=args.context or "")
    client = _get_client(args.mock)
    response = client.chat([{"role": "user", "content": prompt}])
    print(response.content)


def cmd_commit(args: argparse.Namespace) -> None:
    diff = args.diff or _read_input(None)
    prompt = PromptTemplate(COMMIT_MESSAGE).format(diff=diff)
    client = _get_client(args.mock)
    response = client.chat([{"role": "user", "content": prompt}])
    print(response.content)


def cmd_security(args: argparse.Namespace) -> None:
    code = _read_input(args.file)
    prompt = PromptTemplate(SECURITY_REVIEW).format(code=code)
    client = _get_client(args.mock)
    response = client.chat([{"role": "user", "content": prompt}])
    print(response.content)


def cmd_refactor(args: argparse.Namespace) -> None:
    code = _read_input(args.file)
    prompt = PromptTemplate(REFACTOR).format(code=code, goal=args.goal)
    client = _get_client(args.mock)
    response = client.chat([{"role": "user", "content": prompt}])
    print(response.content)


def cmd_tests(args: argparse.Namespace) -> None:
    code = _read_input(args.file)
    prompt = PromptTemplate(GENERATE_TESTS).format(code=code, framework=args.framework)
    client = _get_client(args.mock)
    response = client.chat([{"role": "user", "content": prompt}])
    print(response.content)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="devai",
        description="DevAI — AI tools for developers",
    )
    parser.add_argument("--mock", action="store_true", help="Use mock LLM client")
    subparsers = parser.add_subparsers(dest="command", required=True)

    review = subparsers.add_parser("review", help="Review code for issues")
    review.add_argument("file", nargs="?", help="Source file to review")
    review.add_argument("--context", help="Additional context")
    review.set_defaults(func=cmd_review)

    explain = subparsers.add_parser("explain", help="Explain code")
    explain.add_argument("code", nargs="?", help="Code to explain")
    explain.add_argument("--file", "-f", help="Source file")
    explain.add_argument("--language", "-l", default="python")
    explain.set_defaults(func=cmd_explain)

    debug = subparsers.add_parser("debug", help="Debug an error")
    debug.add_argument("--error", "-e", required=True, help="Error message")
    debug.add_argument("file", nargs="?", help="Source file")
    debug.add_argument("--context", help="Additional context")
    debug.set_defaults(func=cmd_debug)

    commit = subparsers.add_parser("commit", help="Generate commit message from diff")
    commit.add_argument("--diff", "-d", help="Git diff text")
    commit.set_defaults(func=cmd_commit)

    security = subparsers.add_parser("security", help="Security review")
    security.add_argument("file", help="Source file")
    security.set_defaults(func=cmd_security)

    refactor = subparsers.add_parser("refactor", help="Refactor code")
    refactor.add_argument("file", help="Source file")
    refactor.add_argument("--goal", "-g", default="readability and maintainability")
    refactor.set_defaults(func=cmd_refactor)

    tests = subparsers.add_parser("tests", help="Generate unit tests")
    tests.add_argument("file", help="Source file")
    tests.add_argument("--framework", default="pytest")
    tests.set_defaults(func=cmd_tests)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
