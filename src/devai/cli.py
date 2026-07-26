"""DevAI command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message
from devai.prompts import dev


def _get_client(args: argparse.Namespace):
    if args.mock:
        return MockLLMClient()
    return LLMClient(DevAIConfig.from_env())


def _read_input(args: argparse.Namespace) -> str:
    if args.file:
        return Path(args.file).read_text(encoding="utf-8")
    if args.code:
        return args.code
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def cmd_review(args: argparse.Namespace) -> None:
    code = _read_input(args)
    if not code:
        print("Error: provide code via --file, --code, or stdin", file=sys.stderr)
        sys.exit(1)
    language = args.language or "python"
    prompt = dev.CODE_REVIEW.format(language=language, code=code)
    client = _get_client(args)
    response = client.chat([Message.user(prompt)])
    print(response.content or "")


def cmd_explain(args: argparse.Namespace) -> None:
    code = _read_input(args)
    if not code:
        print("Error: provide code via --file, --code, or stdin", file=sys.stderr)
        sys.exit(1)
    language = args.language or "python"
    prompt = dev.EXPLAIN_CODE.format(language=language, code=code)
    client = _get_client(args)
    response = client.chat([Message.user(prompt)])
    print(response.content or "")


def cmd_debug(args: argparse.Namespace) -> None:
    code = _read_input(args)
    error = args.error or ""
    if not code or not error:
        print("Error: provide --error and code via --file/--code/stdin", file=sys.stderr)
        sys.exit(1)
    language = args.language or "python"
    prompt = dev.DEBUG.format(error=error, language=language, code=code)
    client = _get_client(args)
    response = client.chat([Message.user(prompt)])
    print(response.content or "")


def cmd_commit(args: argparse.Namespace) -> None:
    from devai.tools.code import git_diff

    diff = git_diff(staged=args.staged)
    prompt = dev.COMMIT_MESSAGE.format(diff=diff)
    client = _get_client(args)
    response = client.chat([Message.user(prompt)])
    print(response.content or "")


def cmd_security(args: argparse.Namespace) -> None:
    code = _read_input(args)
    if not code:
        print("Error: provide code via --file, --code, or stdin", file=sys.stderr)
        sys.exit(1)
    language = args.language or "python"
    prompt = dev.SECURITY_REVIEW.format(language=language, code=code)
    client = _get_client(args)
    response = client.chat([Message.user(prompt)])
    print(response.content or "")


def cmd_tests(args: argparse.Namespace) -> None:
    code = _read_input(args)
    if not code:
        print("Error: provide code via --file, --code, or stdin", file=sys.stderr)
        sys.exit(1)
    language = args.language or "python"
    framework = args.framework or "pytest"
    prompt = dev.TEST_GENERATION.format(language=language, framework=framework, code=code)
    client = _get_client(args)
    response = client.chat([Message.user(prompt)])
    print(response.content or "")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="devai",
        description="DevAI — AI tools for developers",
    )
    parser.add_argument("--mock", action="store_true", help="Use mock LLM (no API key needed)")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, handler in [
        ("review", cmd_review),
        ("explain", cmd_explain),
        ("debug", cmd_debug),
        ("commit", cmd_commit),
        ("security", cmd_security),
        ("tests", cmd_tests),
    ]:
        p = sub.add_parser(name, help=f"{name} command")
        p.add_argument("--file", "-f", help="Input file path")
        p.add_argument("--code", "-c", help="Inline code string")
        p.add_argument("--language", "-l", default="python", help="Programming language")
        p.set_defaults(func=handler)

    debug_p = sub.choices["debug"]
    debug_p.add_argument("--error", "-e", help="Error message or traceback")

    commit_p = sub.choices["commit"]
    commit_p.add_argument("--staged", action="store_true", help="Use staged diff")

    tests_p = sub.choices["tests"]
    tests_p.add_argument("--framework", default="pytest", help="Test framework")

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
