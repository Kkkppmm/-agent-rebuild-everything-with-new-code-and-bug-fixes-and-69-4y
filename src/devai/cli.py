"""DevAI command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message, Role
from devai.prompts import dev_prompts


def _get_client(mock: bool = False) -> LLMClient | MockLLMClient:
    if mock:
        return MockLLMClient()
    return LLMClient(DevAIConfig.from_env())


def _run_prompt(prompt_name: str, mock: bool, **kwargs: str) -> None:
    template = dev_prompts.ALL_PROMPTS.get(prompt_name)
    if not template:
        print(f"Unknown prompt: {prompt_name}", file=sys.stderr)
        print(f"Available: {', '.join(dev_prompts.ALL_PROMPTS)}", file=sys.stderr)
        sys.exit(1)
    content = template.format(**kwargs)
    client = _get_client(mock)
    messages = [
        Message(role=Role.SYSTEM, content="You are an expert developer assistant."),
        Message(role=Role.USER, content=content),
    ]
    response = client.complete(messages)
    print(response.content)


def cmd_review(args: argparse.Namespace) -> None:
    code = Path(args.file).read_text() if args.file else args.code
    _run_prompt("code_review", args.mock, code=code, language=args.language)


def cmd_explain(args: argparse.Namespace) -> None:
    code = Path(args.file).read_text() if args.file else args.code
    from devai.tools.code_utils import explain_code

    print(explain_code(code, args.language))
    if not args.local_only:
        _run_prompt("code_review", args.mock, code=code, language=args.language)


def cmd_debug(args: argparse.Namespace) -> None:
    code = Path(args.file).read_text() if args.file else args.code
    _run_prompt("debug", args.mock, code=code, error=args.error, language=args.language)


def cmd_commit(args: argparse.Namespace) -> None:
    from devai.tools.code_utils import git_diff

    diff = git_diff(args.cwd)
    _run_prompt("commit_message", args.mock, diff=diff)


def cmd_tests(args: argparse.Namespace) -> None:
    code = Path(args.file).read_text()
    _run_prompt(
        "test_gen",
        args.mock,
        code=code,
        language=args.language,
        framework=args.framework,
    )


def cmd_security(args: argparse.Namespace) -> None:
    code = Path(args.file).read_text() if args.file else args.code
    _run_prompt("security_review", args.mock, code=code, language=args.language)


def cmd_refactor(args: argparse.Namespace) -> None:
    code = Path(args.file).read_text() if args.file else args.code
    _run_prompt("refactor", args.mock, code=code, language=args.language)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="devai",
        description="DevAI — AI tools for developers",
    )
    parser.add_argument("--mock", action="store_true", help="Use mock LLM (no API key needed)")
    sub = parser.add_subparsers(dest="command", required=True)

    # review
    p = sub.add_parser("review", help="Review code")
    p.add_argument("--file", "-f", help="Source file path")
    p.add_argument("--code", "-c", help="Inline code string")
    p.add_argument("--language", "-l", default="python")
    p.set_defaults(func=cmd_review)

    # explain
    p = sub.add_parser("explain", help="Explain code structure")
    p.add_argument("--file", "-f", help="Source file path")
    p.add_argument("--code", "-c", help="Inline code string")
    p.add_argument("--language", "-l", default="python")
    p.add_argument("--local-only", action="store_true", help="Skip LLM analysis")
    p.set_defaults(func=cmd_explain)

    # debug
    p = sub.add_parser("debug", help="Debug an error")
    p.add_argument("--file", "-f", help="Source file path")
    p.add_argument("--code", "-c", help="Inline code string")
    p.add_argument("--error", "-e", required=True, help="Error message")
    p.add_argument("--language", "-l", default="python")
    p.set_defaults(func=cmd_debug)

    # commit
    p = sub.add_parser("commit", help="Generate commit message from git diff")
    p.add_argument("--cwd", default=".", help="Git working directory")
    p.set_defaults(func=cmd_commit)

    # tests
    p = sub.add_parser("tests", help="Generate unit tests")
    p.add_argument("--file", "-f", required=True, help="Source file path")
    p.add_argument("--language", "-l", default="python")
    p.add_argument("--framework", default="pytest")
    p.set_defaults(func=cmd_tests)

    # security
    p = sub.add_parser("security", help="Security review")
    p.add_argument("--file", "-f", help="Source file path")
    p.add_argument("--code", "-c", help="Inline code string")
    p.add_argument("--language", "-l", default="python")
    p.set_defaults(func=cmd_security)

    # refactor
    p = sub.add_parser("refactor", help="Refactor code")
    p.add_argument("--file", "-f", help="Source file path")
    p.add_argument("--code", "-c", help="Inline code string")
    p.add_argument("--language", "-l", default="python")
    p.set_defaults(func=cmd_refactor)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
