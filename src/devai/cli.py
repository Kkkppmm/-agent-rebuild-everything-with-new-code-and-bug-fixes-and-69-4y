"""Command-line interface for DevAI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from devai import Chain, DevAIConfig
from devai.prompts import (
    CODE_REVIEW,
    COMMIT_MESSAGE,
    DEBUG,
    DOCSTRING,
    EXPLAIN_CODE,
    REFACTOR,
    SECURITY_REVIEW,
    WRITE_TESTS,
)
from devai.tools.code_utils import git_diff, read_file


def _detect_language(path: str) -> str:
    ext = Path(path).suffix.lower()
    return {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".go": "go",
        ".rs": "rust",
        ".java": "java",
        ".rb": "ruby",
        ".cpp": "cpp",
        ".c": "c",
    }.get(ext, "text")


def _run_chain(prompt, **kwargs: str) -> int:
    try:
        config = DevAIConfig.from_env()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    chain = Chain(prompt, config=config)
    try:
        result = chain.run_sync(**kwargs)
        print(result)
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    finally:
        import asyncio

        asyncio.run(chain.close())


def cmd_review(args: argparse.Namespace) -> int:
    code = read_file(args.file)
    if code.startswith("Error:"):
        print(code, file=sys.stderr)
        return 1
    return _run_chain(
        CODE_REVIEW,
        code=code,
        language=_detect_language(args.file),
    )


def cmd_explain(args: argparse.Namespace) -> int:
    code = read_file(args.file)
    if code.startswith("Error:"):
        print(code, file=sys.stderr)
        return 1
    return _run_chain(
        EXPLAIN_CODE,
        code=code,
        language=_detect_language(args.file),
        audience=args.audience,
    )


def cmd_debug(args: argparse.Namespace) -> int:
    code = read_file(args.file) if args.file else args.code or ""
    if not code or code.startswith("Error:"):
        print("Error: provide --file or --code", file=sys.stderr)
        return 1
    return _run_chain(
        DEBUG,
        language=args.language or (_detect_language(args.file) if args.file else "python"),
        error=args.error,
        code=code,
        context=args.context or "No additional context",
    )


def cmd_commit(args: argparse.Namespace) -> int:
    diff = git_diff(staged=args.staged)
    if diff.startswith("Error:"):
        print(diff, file=sys.stderr)
        return 1
    return _run_chain(COMMIT_MESSAGE, diff=diff)


def cmd_tests(args: argparse.Namespace) -> int:
    code = read_file(args.file)
    if code.startswith("Error:"):
        print(code, file=sys.stderr)
        return 1
    return _run_chain(
        WRITE_TESTS,
        code=code,
        language=_detect_language(args.file),
        framework=args.framework,
    )


def cmd_docstring(args: argparse.Namespace) -> int:
    code = read_file(args.file)
    if code.startswith("Error:"):
        print(code, file=sys.stderr)
        return 1
    return _run_chain(
        DOCSTRING,
        code=code,
        language=_detect_language(args.file),
        style=args.style,
    )


def cmd_refactor(args: argparse.Namespace) -> int:
    code = read_file(args.file)
    if code.startswith("Error:"):
        print(code, file=sys.stderr)
        return 1
    return _run_chain(
        REFACTOR,
        code=code,
        language=_detect_language(args.file),
        goal=args.goal,
    )


def cmd_security(args: argparse.Namespace) -> int:
    code = read_file(args.file)
    if code.startswith("Error:"):
        print(code, file=sys.stderr)
        return 1
    return _run_chain(
        SECURITY_REVIEW,
        code=code,
        language=_detect_language(args.file),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devai",
        description="DevAI — AI tools for developers",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    review = sub.add_parser("review", help="Review code for bugs and style issues")
    review.add_argument("file", help="Source file to review")
    review.set_defaults(func=cmd_review)

    explain = sub.add_parser("explain", help="Explain what code does")
    explain.add_argument("file", help="Source file to explain")
    explain.add_argument(
        "--audience",
        default="intermediate",
        help="Target audience level (default: intermediate)",
    )
    explain.set_defaults(func=cmd_explain)

    debug = sub.add_parser("debug", help="Debug an error in code")
    debug.add_argument("--error", required=True, help="Error message")
    debug.add_argument("--file", help="Source file with the bug")
    debug.add_argument("--code", help="Inline code snippet")
    debug.add_argument("--language", help="Programming language")
    debug.add_argument("--context", help="Additional context")
    debug.set_defaults(func=cmd_debug)

    commit = sub.add_parser("commit", help="Generate a commit message from git diff")
    commit.add_argument("--staged", action="store_true", help="Use staged changes only")
    commit.set_defaults(func=cmd_commit)

    tests = sub.add_parser("tests", help="Generate unit tests for code")
    tests.add_argument("file", help="Source file to test")
    tests.add_argument("--framework", default="pytest", help="Test framework")
    tests.set_defaults(func=cmd_tests)

    docstring = sub.add_parser("docstring", help="Add docstrings to code")
    docstring.add_argument("file", help="Source file")
    docstring.add_argument("--style", default="Google", help="Docstring style")
    docstring.set_defaults(func=cmd_docstring)

    refactor = sub.add_parser("refactor", help="Refactor code for a goal")
    refactor.add_argument("file", help="Source file")
    refactor.add_argument(
        "--goal",
        default="readability and maintainability",
        help="Refactoring goal",
    )
    refactor.set_defaults(func=cmd_refactor)

    security = sub.add_parser("security", help="Security review of code")
    security.add_argument("file", help="Source file to audit")
    security.set_defaults(func=cmd_security)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
