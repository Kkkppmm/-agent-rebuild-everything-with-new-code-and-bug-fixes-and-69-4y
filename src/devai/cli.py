"""DevAI command-line interface."""

import argparse
import sys

from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.chains.chain import Chain
from devai.prompts.dev_prompts import (
    CODE_REVIEW,
    DEBUG,
    COMMIT_MESSAGE,
    SECURITY_REVIEW,
    REFACTOR,
    EXPLAIN_CODE,
    GENERATE_TESTS,
)


def _get_client(use_mock: bool) -> LLMClient | MockLLMClient:
    if use_mock:
        return MockLLMClient(responses=["[Mock] Analysis complete. Configure OPENAI_API_KEY for real results."])
    return LLMClient(DevAIConfig())


def _read_input(path: str | None) -> str:
    if path:
        with open(path, encoding="utf-8") as f:
            return f.read()
    return sys.stdin.read()


def cmd_review(args: argparse.Namespace) -> None:
    code = _read_input(args.file)
    chain = Chain(_get_client(args.mock), CODE_REVIEW)
    print(chain.run(code=code, language=args.language, context=args.context or "None"))


def cmd_explain(args: argparse.Namespace) -> None:
    code = _read_input(args.file)
    chain = Chain(_get_client(args.mock), EXPLAIN_CODE)
    print(chain.run(code=code, language=args.language, audience=args.audience))


def cmd_debug(args: argparse.Namespace) -> None:
    code = _read_input(args.file)
    chain = Chain(_get_client(args.mock), DEBUG)
    print(chain.run(
        error=args.error,
        code=code,
        language=args.language,
        stack_trace=args.stack_trace or "Not provided",
    ))


def cmd_commit(args: argparse.Namespace) -> None:
    from devai.tools.code_tools import git_diff
    diff = git_diff(args.path, staged=args.staged)
    chain = Chain(_get_client(args.mock), COMMIT_MESSAGE)
    print(chain.run(diff=diff))


def cmd_tests(args: argparse.Namespace) -> None:
    code = _read_input(args.file)
    chain = Chain(_get_client(args.mock), GENERATE_TESTS)
    print(chain.run(
        code=code,
        language=args.language,
        framework=args.framework,
    ))


def cmd_security(args: argparse.Namespace) -> None:
    code = _read_input(args.file)
    chain = Chain(_get_client(args.mock), SECURITY_REVIEW)
    print(chain.run(code=code, language=args.language))


def cmd_refactor(args: argparse.Namespace) -> None:
    code = _read_input(args.file)
    chain = Chain(_get_client(args.mock), REFACTOR)
    print(chain.run(
        code=code,
        language=args.language,
        goal=args.goal,
        constraints=args.constraints or "Preserve behavior",
    ))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="devai",
        description="DevAI — AI tools for developers",
    )
    parser.add_argument("--mock", action="store_true", help="Use mock client (no API key needed)")
    sub = parser.add_subparsers(dest="command", required=True)

    review = sub.add_parser("review", help="Review code")
    review.add_argument("-f", "--file", help="File to review")
    review.add_argument("-l", "--language", default="python")
    review.add_argument("-c", "--context", default="")
    review.set_defaults(func=cmd_review)

    explain = sub.add_parser("explain", help="Explain code")
    explain.add_argument("-f", "--file", help="File to explain")
    explain.add_argument("-l", "--language", default="python")
    explain.add_argument("-a", "--audience", default="intermediate")
    explain.set_defaults(func=cmd_explain)

    debug = sub.add_parser("debug", help="Debug an error")
    debug.add_argument("-f", "--file", help="Source file")
    debug.add_argument("-e", "--error", required=True, help="Error message")
    debug.add_argument("-l", "--language", default="python")
    debug.add_argument("-s", "--stack-trace", default="")
    debug.set_defaults(func=cmd_debug)

    commit = sub.add_parser("commit", help="Generate commit message from diff")
    commit.add_argument("-p", "--path", default=".")
    commit.add_argument("--staged", action="store_true")
    commit.set_defaults(func=cmd_commit)

    tests = sub.add_parser("tests", help="Generate tests")
    tests.add_argument("-f", "--file", help="Source file")
    tests.add_argument("-l", "--language", default="python")
    tests.add_argument("--framework", default="pytest")
    tests.set_defaults(func=cmd_tests)

    security = sub.add_parser("security", help="Security review")
    security.add_argument("-f", "--file", help="File to review")
    security.add_argument("-l", "--language", default="python")
    security.set_defaults(func=cmd_security)

    refactor = sub.add_parser("refactor", help="Refactor code")
    refactor.add_argument("-f", "--file", help="Source file")
    refactor.add_argument("-l", "--language", default="python")
    refactor.add_argument("-g", "--goal", default="improve readability")
    refactor.add_argument("--constraints", default="")
    refactor.set_defaults(func=cmd_refactor)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
