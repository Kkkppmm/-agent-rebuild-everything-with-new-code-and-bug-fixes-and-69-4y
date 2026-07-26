"""Command-line interface for DevAI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from devai import DevAIConfig, LLMClient, MockLLMClient
from devai.agents import CoderAgent
from devai.prompts import (
    CODE_REVIEW,
    COMMIT_MESSAGE,
    DEBUG,
    EXPLAIN_CODE,
    GENERATE_TESTS,
    REFACTOR,
    SECURITY_REVIEW,
)


def _get_client(config: DevAIConfig) -> LLMClient | MockLLMClient:
    if config.api_key:
        return LLMClient(config)
    print("No API key found — using mock client.", file=sys.stderr)
    return MockLLMClient()


def _read_file(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def cmd_review(args: argparse.Namespace) -> None:
    config = DevAIConfig()
    client = _get_client(config)
    code = _read_file(args.file)
    language = args.language or Path(args.file).suffix.lstrip(".") or "text"
    prompt = CODE_REVIEW.format(code=code, language=language)
    print(client.chat(prompt))


def cmd_explain(args: argparse.Namespace) -> None:
    config = DevAIConfig()
    client = _get_client(config)
    if args.file:
        code = _read_file(args.file)
        language = args.language or Path(args.file).suffix.lstrip(".") or "text"
    else:
        code = args.code
        language = args.language or "python"
    prompt = EXPLAIN_CODE.format(code=code, language=language)
    print(client.chat(prompt))


def cmd_debug(args: argparse.Namespace) -> None:
    config = DevAIConfig()
    client = _get_client(config)
    code = _read_file(args.file) if args.file else args.code
    language = args.language or "python"
    prompt = DEBUG.format(code=code, error=args.error, language=language)
    print(client.chat(prompt))


def cmd_commit(args: argparse.Namespace) -> None:
    from devai.tools import git_diff

    config = DevAIConfig()
    client = _get_client(config)
    diff = git_diff(staged=args.staged)
    prompt = COMMIT_MESSAGE.format(diff=diff)
    print(client.chat(prompt))


def cmd_tests(args: argparse.Namespace) -> None:
    config = DevAIConfig()
    client = _get_client(config)
    code = _read_file(args.file)
    language = args.language or Path(args.file).suffix.lstrip(".") or "python"
    prompt = GENERATE_TESTS.format(code=code, language=language, framework=args.framework)
    print(client.chat(prompt))


def cmd_security(args: argparse.Namespace) -> None:
    config = DevAIConfig()
    client = _get_client(config)
    code = _read_file(args.file)
    language = args.language or Path(args.file).suffix.lstrip(".") or "text"
    prompt = SECURITY_REVIEW.format(code=code, language=language)
    print(client.chat(prompt))


def cmd_refactor(args: argparse.Namespace) -> None:
    config = DevAIConfig()
    client = _get_client(config)
    code = _read_file(args.file)
    language = args.language or Path(args.file).suffix.lstrip(".") or "python"
    goals = args.goals or "improve readability and maintainability"
    prompt = REFACTOR.format(code=code, language=language, goals=goals)
    print(client.chat(prompt))


def cmd_agent(args: argparse.Namespace) -> None:
    config = DevAIConfig()
    client = _get_client(config)
    agent = CoderAgent(client, config)
    print(agent.run(args.prompt))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="devai", description="DevAI CLI for developers")
    sub = parser.add_subparsers(dest="command", required=True)

    review = sub.add_parser("review", help="Review code in a file")
    review.add_argument("file")
    review.add_argument("--language", "-l")
    review.set_defaults(func=cmd_review)

    explain = sub.add_parser("explain", help="Explain code")
    explain.add_argument("code", nargs="?", default="")
    explain.add_argument("--file", "-f")
    explain.add_argument("--language", "-l")
    explain.set_defaults(func=cmd_explain)

    debug = sub.add_parser("debug", help="Debug an error")
    debug.add_argument("error")
    debug.add_argument("--file", "-f")
    debug.add_argument("--code", "-c", default="")
    debug.add_argument("--language", "-l")
    debug.set_defaults(func=cmd_debug)

    commit = sub.add_parser("commit", help="Generate commit message from diff")
    commit.add_argument("--staged", action="store_true")
    commit.set_defaults(func=cmd_commit)

    tests = sub.add_parser("tests", help="Generate unit tests")
    tests.add_argument("file")
    tests.add_argument("--language", "-l")
    tests.add_argument("--framework", default="pytest")
    tests.set_defaults(func=cmd_tests)

    security = sub.add_parser("security", help="Security review")
    security.add_argument("file")
    security.add_argument("--language", "-l")
    security.set_defaults(func=cmd_security)

    refactor = sub.add_parser("refactor", help="Refactor code")
    refactor.add_argument("file")
    refactor.add_argument("--language", "-l")
    refactor.add_argument("--goals", "-g")
    refactor.set_defaults(func=cmd_refactor)

    agent = sub.add_parser("agent", help="Run coder agent")
    agent.add_argument("prompt")
    agent.set_defaults(func=cmd_agent)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
