"""Command-line interface for DevAI."""

from __future__ import annotations

import argparse
import sys

from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.prompts import dev_prompts


def _get_client(use_mock: bool) -> LLMClient | MockLLMClient:
    if use_mock:
        return MockLLMClient()
    return LLMClient(DevAIConfig.from_env())


def cmd_review(args: argparse.Namespace) -> None:
    code = args.file.read() if args.file else args.code
    if not code:
        print("Error: provide --file or --code", file=sys.stderr)
        sys.exit(1)
    client = _get_client(args.mock)
    prompt = dev_prompts.CODE_REVIEW.format(
        language=args.language, code=code, extra_instructions=""
    )
    print(client.complete(prompt))


def cmd_explain(args: argparse.Namespace) -> None:
    code = args.file.read() if args.file else args.code
    if not code:
        print("Error: provide --file or --code", file=sys.stderr)
        sys.exit(1)
    client = _get_client(args.mock)
    prompt = dev_prompts.EXPLAIN_CODE.format(language=args.language, code=code)
    print(client.complete(prompt))


def cmd_debug(args: argparse.Namespace) -> None:
    client = _get_client(args.mock)
    code = ""
    if args.file:
        code = args.file.read()
    prompt = dev_prompts.DEBUG.format(
        error=args.error, language=args.language, code=code, stack_trace=args.trace or ""
    )
    print(client.complete(prompt))


def cmd_commit(args: argparse.Namespace) -> None:
    import subprocess

    diff = subprocess.run(["git", "diff", "--staged"], capture_output=True, text=True).stdout
    if not diff:
        diff = subprocess.run(["git", "diff"], capture_output=True, text=True).stdout
    client = _get_client(args.mock)
    prompt = dev_prompts.COMMIT_MESSAGE.format(diff=diff or "No changes")
    print(client.complete(prompt))


def cmd_tests(args: argparse.Namespace) -> None:
    code = args.file.read() if args.file else args.code
    client = _get_client(args.mock)
    prompt = dev_prompts.GENERATE_TESTS.format(
        language=args.language, code=code, framework=args.framework
    )
    print(client.complete(prompt))


def cmd_security(args: argparse.Namespace) -> None:
    code = args.file.read() if args.file else args.code
    client = _get_client(args.mock)
    prompt = dev_prompts.SECURITY_REVIEW.format(language=args.language, code=code)
    print(client.complete(prompt))


def cmd_refactor(args: argparse.Namespace) -> None:
    code = args.file.read() if args.file else args.code
    if not code:
        print("Error: provide --file or --code", file=sys.stderr)
        sys.exit(1)
    client = _get_client(args.mock)
    prompt = dev_prompts.REFACTOR.format(
        language=args.language, code=code, goals=args.goals
    )
    print(client.complete(prompt))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="devai",
        description="DevAI — AI tools for developers",
    )
    parser.add_argument("--mock", action="store_true", help="Use mock LLM (no API key needed)")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, func, help_text in [
        ("review", cmd_review, "Review code for issues"),
        ("explain", cmd_explain, "Explain what code does"),
        ("debug", cmd_debug, "Debug an error"),
        ("commit", cmd_commit, "Generate a commit message from git diff"),
        ("tests", cmd_tests, "Generate unit tests"),
        ("security", cmd_security, "Security review of code"),
        ("refactor", cmd_refactor, "Refactor code for clarity"),
    ]:
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--file", type=argparse.FileType("r"), help="Input file")
        p.add_argument("--code", help="Inline code string")
        p.add_argument("--language", default="python", help="Programming language")
        if name == "debug":
            p.add_argument("--error", required=True, help="Error message")
            p.add_argument("--trace", help="Stack trace")
        if name == "tests":
            p.add_argument("--framework", default="pytest", help="Test framework")
        if name == "refactor":
            p.add_argument(
                "--goals",
                default="improve readability and maintainability",
                help="Refactoring goals",
            )
        p.set_defaults(func=func)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
