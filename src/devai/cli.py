"""DevAI command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from devai import MockLLMClient
from devai.agents.coder import CoderAgent
from devai.core.client import LLMClient
from devai.core.config import DevAIConfig
from devai.core.models import Message, Role
from devai.prompts import ALL_PROMPTS


def _get_client(use_mock: bool = False) -> LLMClient | MockLLMClient:
    if use_mock:
        return MockLLMClient()
    config = DevAIConfig.from_env()
    if not config.api_key:
        print("Warning: No API key found. Set OPENAI_API_KEY or use --mock.", file=sys.stderr)
        return MockLLMClient()
    return LLMClient(config)


def cmd_review(args: argparse.Namespace) -> None:
    code = Path(args.file).read_text() if args.file else args.code or sys.stdin.read()
    language = args.language or "python"
    if args.agent:
        agent = CoderAgent(_get_client(args.mock))
        print(agent.review(code, language))
    else:
        prompt = ALL_PROMPTS["code_review"].format(language=language, code=code)
        client = _get_client(args.mock)
        response = client.complete([
            Message(role=Role.USER, content=prompt),
        ])
        print(response.content)


def cmd_explain(args: argparse.Namespace) -> None:
    code = Path(args.file).read_text() if args.file else args.code or sys.stdin.read()
    language = args.language or "python"
    prompt = ALL_PROMPTS["explain_code"].format(language=language, code=code)
    client = _get_client(args.mock)
    response = client.complete([Message(role=Role.USER, content=prompt)])
    print(response.content)


def cmd_debug(args: argparse.Namespace) -> None:
    code = Path(args.file).read_text() if args.file else args.code or ""
    error = args.error or sys.stdin.read()
    language = args.language or "python"
    prompt = ALL_PROMPTS["debug"].format(language=language, code=code, error=error)
    client = _get_client(args.mock)
    response = client.complete([Message(role=Role.USER, content=prompt)])
    print(response.content)


def cmd_commit(args: argparse.Namespace) -> None:
    import subprocess

    diff = subprocess.run(["git", "diff", "--cached"], capture_output=True, text=True).stdout
    if not diff:
        diff = subprocess.run(["git", "diff"], capture_output=True, text=True).stdout
    prompt = ALL_PROMPTS["commit_message"].format(diff=diff or "No changes")
    client = _get_client(args.mock)
    response = client.complete([Message(role=Role.USER, content=prompt)])
    print(response.content)


def cmd_security(args: argparse.Namespace) -> None:
    code = Path(args.file).read_text() if args.file else args.code or sys.stdin.read()
    language = args.language or "python"
    prompt = ALL_PROMPTS["security_review"].format(language=language, code=code)
    client = _get_client(args.mock)
    response = client.complete([Message(role=Role.USER, content=prompt)])
    print(response.content)


def cmd_refactor(args: argparse.Namespace) -> None:
    code = Path(args.file).read_text() if args.file else args.code or sys.stdin.read()
    language = args.language or "python"
    goal = args.goal or "readability"
    prompt = ALL_PROMPTS["refactor"].format(language=language, code=code, goal=goal)
    client = _get_client(args.mock)
    response = client.complete([Message(role=Role.USER, content=prompt)])
    print(response.content)


def cmd_tests(args: argparse.Namespace) -> None:
    code = Path(args.file).read_text() if args.file else args.code or sys.stdin.read()
    language = args.language or "python"
    framework = args.framework or "pytest"
    prompt = ALL_PROMPTS["unit_test"].format(
        language=language, code=code, framework=framework
    )
    client = _get_client(args.mock)
    response = client.complete([Message(role=Role.USER, content=prompt)])
    print(response.content)


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
        ("refactor", cmd_refactor),
        ("tests", cmd_tests),
    ]:
        p = sub.add_parser(name, help=f"AI-powered {name}")
        p.add_argument("-f", "--file", help="Source file path")
        p.add_argument("-c", "--code", help="Inline code string")
        p.add_argument("-l", "--language", default="python", help="Programming language")
        p.set_defaults(func=handler)

    review_p = sub.choices["review"]
    review_p.add_argument("--agent", action="store_true", help="Use CoderAgent with tools")

    debug_p = sub.choices["debug"]
    debug_p.add_argument("-e", "--error", help="Error message")

    refactor_p = sub.choices["refactor"]
    refactor_p.add_argument("-g", "--goal", default="readability", help="Refactor goal")

    tests_p = sub.choices["tests"]
    tests_p.add_argument("--framework", default="pytest", help="Test framework")

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
