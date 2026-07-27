"""CLI for DevAI — developer AI tasks from the command line."""

import argparse
import sys
from pathlib import Path

from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.prompts import (
    PromptTemplate,
    CODE_REVIEW,
    DEBUG,
    COMMIT_MESSAGE,
    SECURITY_REVIEW,
    REFACTOR,
    EXPLAIN_CODE,
    TEST_GEN,
)
from devai.agents import CoderAgent
from devai.tools import ToolRegistry, explain_code, lint_python, read_file, search_code, count_complexity


def _get_client(use_mock: bool = False) -> LLMClient | MockLLMClient:
    if use_mock:
        return MockLLMClient()
    config = DevAIConfig()
    if not config.api_key:
        print("Warning: No API key found. Using mock client. Set DEVAI_API_KEY to use a real provider.")
        return MockLLMClient()
    return LLMClient(config)


def _read_code(args: argparse.Namespace) -> str:
    if args.code:
        return args.code
    if getattr(args, "file", None):
        return Path(args.file).read_text()
    return ""


def cmd_review(args: argparse.Namespace) -> None:
    client = _get_client(args.mock)
    code = _read_code(args)
    if not code:
        print("Error: provide --code or --file")
        sys.exit(1)
    prompt = PromptTemplate(CODE_REVIEW).format(code=code, language=args.language)
    response = client.complete(prompt)
    print(response.content)


def cmd_explain(args: argparse.Namespace) -> None:
    client = _get_client(args.mock)
    code = _read_code(args)
    if not code:
        print("Error: provide --code or --file")
        sys.exit(1)
    prompt = PromptTemplate(EXPLAIN_CODE).format(code=code, language=args.language)
    response = client.complete(prompt)
    print(response.content)


def cmd_debug(args: argparse.Namespace) -> None:
    client = _get_client(args.mock)
    code = _read_code(args)
    prompt = PromptTemplate(DEBUG).format(error=args.error, code=code)
    response = client.complete(prompt)
    print(response.content)


def cmd_commit(args: argparse.Namespace) -> None:
    client = _get_client(args.mock)
    diff = args.diff or ""
    if args.staged:
        from devai.tools import git_diff
        diff = git_diff(staged=True)
    prompt = PromptTemplate(COMMIT_MESSAGE).format(diff=diff)
    response = client.complete(prompt)
    print(response.content)


def cmd_security(args: argparse.Namespace) -> None:
    client = _get_client(args.mock)
    code = _read_code(args)
    if not code:
        print("Error: provide --code or --file")
        sys.exit(1)
    prompt = PromptTemplate(SECURITY_REVIEW).format(code=code)
    response = client.complete(prompt)
    print(response.content)


def cmd_refactor(args: argparse.Namespace) -> None:
    client = _get_client(args.mock)
    code = _read_code(args)
    if not code:
        print("Error: provide --code or --file")
        sys.exit(1)
    prompt = PromptTemplate(REFACTOR).format(code=code, goals=args.goals)
    response = client.complete(prompt)
    print(response.content)


def cmd_tests(args: argparse.Namespace) -> None:
    client = _get_client(args.mock)
    code = _read_code(args)
    if not code:
        print("Error: provide --code or --file")
        sys.exit(1)
    prompt = PromptTemplate(TEST_GEN).format(code=code, framework=args.framework)
    response = client.complete(prompt)
    print(response.content)


def cmd_agent(args: argparse.Namespace) -> None:
    client = _get_client(args.mock)
    registry = ToolRegistry()
    registry.register(explain_code)
    registry.register(lint_python)
    registry.register(read_file)
    registry.register(search_code)
    registry.register(count_complexity)
    agent = CoderAgent(client=client, tools=registry)
    result = agent.run(args.task)
    print(result)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="devai",
        description="DevAI — AI tools for developers",
    )
    parser.add_argument("--mock", action="store_true", help="Use mock client (no API key needed)")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # review
    p_review = subparsers.add_parser("review", help="Review code")
    p_review.add_argument("--file", "-f", help="File to review")
    p_review.add_argument("--code", "-c", help="Code string to review")
    p_review.add_argument("--language", "-l", default="python", help="Language")
    p_review.set_defaults(func=cmd_review)

    # explain
    p_explain = subparsers.add_parser("explain", help="Explain code")
    p_explain.add_argument("--file", "-f", help="File to explain")
    p_explain.add_argument("--code", "-c", help="Code string to explain")
    p_explain.add_argument("--language", "-l", default="python", help="Language")
    p_explain.set_defaults(func=cmd_explain)

    # debug
    p_debug = subparsers.add_parser("debug", help="Debug an issue")
    p_debug.add_argument("--error", "-e", required=True, help="Error message or description")
    p_debug.add_argument("--file", "-f", help="File with code context")
    p_debug.add_argument("--code", "-c", help="Code context string")
    p_debug.set_defaults(func=cmd_debug)

    # commit
    p_commit = subparsers.add_parser("commit", help="Generate commit message")
    p_commit.add_argument("--diff", "-d", help="Diff text")
    p_commit.add_argument("--staged", action="store_true", help="Use staged git diff")
    p_commit.set_defaults(func=cmd_commit)

    # security
    p_security = subparsers.add_parser("security", help="Security review")
    p_security.add_argument("--file", "-f", help="File to review")
    p_security.add_argument("--code", "-c", help="Code string to review")
    p_security.set_defaults(func=cmd_security)

    # refactor
    p_refactor = subparsers.add_parser("refactor", help="Refactor code")
    p_refactor.add_argument("--file", "-f", help="File to refactor")
    p_refactor.add_argument("--code", "-c", help="Code string")
    p_refactor.add_argument("--goals", "-g", default="readability and maintainability")
    p_refactor.set_defaults(func=cmd_refactor)

    # tests
    p_tests = subparsers.add_parser("tests", help="Generate tests")
    p_tests.add_argument("--file", "-f", help="File to test")
    p_tests.add_argument("--code", "-c", help="Code string")
    p_tests.add_argument("--framework", default="pytest")
    p_tests.set_defaults(func=cmd_tests)

    # agent
    p_agent = subparsers.add_parser("agent", help="Run coding agent")
    p_agent.add_argument("--task", "-t", required=True, help="Task for the agent")
    p_agent.set_defaults(func=cmd_agent)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
