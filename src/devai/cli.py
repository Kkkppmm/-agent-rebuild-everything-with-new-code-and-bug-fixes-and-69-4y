"""Command-line interface for DevAI."""

from __future__ import annotations

import argparse
import sys

from devai.core.client import LLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message, Role
from devai.prompts.templates import (
    CODE_REVIEW,
    COMMIT_MESSAGE,
    DEBUG,
    EXPLAIN_CODE,
    REFACTOR,
    SECURITY_REVIEW,
    TEST_GEN,
)


def _run_template(template, **kwargs: str) -> None:
    config = DevAIConfig.from_env()
    if not config.api_key:
        print("Error: Set DEVAI_API_KEY or OPENAI_API_KEY environment variable.")
        sys.exit(1)

    client = LLMClient(config)
    msgs = [Message(role=Role.SYSTEM, content=template.system)]
    msgs.append(Message(role=Role.USER, content=template.render(**kwargs)))
    response = client.chat(msgs)
    print(response.content)


def cmd_review(args: argparse.Namespace) -> None:
    code = args.file.read() if args.file else args.code
    _run_template(CODE_REVIEW, language=args.language, code=code)


def cmd_explain(args: argparse.Namespace) -> None:
    code = args.file.read() if args.file else args.code
    _run_template(EXPLAIN_CODE, language=args.language, code=code)


def cmd_debug(args: argparse.Namespace) -> None:
    code = args.file.read() if args.file else args.code
    _run_template(DEBUG, error=args.error, code=code, context=args.context or "N/A")


def cmd_commit(args: argparse.Namespace) -> None:
    from devai.tools.code import git_diff

    diff = git_diff(staged=args.staged)
    _run_template(COMMIT_MESSAGE, diff=diff)


def cmd_tests(args: argparse.Namespace) -> None:
    code = args.file.read() if args.file else args.code
    _run_template(TEST_GEN, code=code, framework=args.framework)


def cmd_security(args: argparse.Namespace) -> None:
    code = args.file.read() if args.file else args.code
    _run_template(SECURITY_REVIEW, code=code)


def cmd_refactor(args: argparse.Namespace) -> None:
    code = args.file.read() if args.file else args.code
    _run_template(REFACTOR, code=code, goal=args.goal)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="devai",
        description="DevAI — AI tools for developers",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # review
    p = sub.add_parser("review", help="Review code for bugs and style")
    p.add_argument("code", nargs="?", default="")
    p.add_argument("-f", "--file", type=argparse.FileType("r"))
    p.add_argument("-l", "--language", default="python")
    p.set_defaults(func=cmd_review)

    # explain
    p = sub.add_parser("explain", help="Explain code")
    p.add_argument("code", nargs="?", default="")
    p.add_argument("-f", "--file", type=argparse.FileType("r"))
    p.add_argument("-l", "--language", default="python")
    p.set_defaults(func=cmd_explain)

    # debug
    p = sub.add_parser("debug", help="Debug an error")
    p.add_argument("error")
    p.add_argument("code", nargs="?", default="")
    p.add_argument("-f", "--file", type=argparse.FileType("r"))
    p.add_argument("-c", "--context", default="")
    p.set_defaults(func=cmd_debug)

    # commit
    p = sub.add_parser("commit", help="Generate commit message from diff")
    p.add_argument("--staged", action="store_true")
    p.set_defaults(func=cmd_commit)

    # tests
    p = sub.add_parser("tests", help="Generate unit tests")
    p.add_argument("code", nargs="?", default="")
    p.add_argument("-f", "--file", type=argparse.FileType("r"))
    p.add_argument("--framework", default="pytest")
    p.set_defaults(func=cmd_tests)

    # security
    p = sub.add_parser("security", help="Security review")
    p.add_argument("code", nargs="?", default="")
    p.add_argument("-f", "--file", type=argparse.FileType("r"))
    p.set_defaults(func=cmd_security)

    # refactor
    p = sub.add_parser("refactor", help="Refactor code")
    p.add_argument("code", nargs="?", default="")
    p.add_argument("-f", "--file", type=argparse.FileType("r"))
    p.add_argument("-g", "--goal", default="readability")
    p.set_defaults(func=cmd_refactor)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
