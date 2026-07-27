"""Command-line interface for DevAI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from devai import CodeAssistant, DevAIConfig, MockLLMClient
from devai.agents import CoderAgent
from devai.tools import git_diff


def _read_input(path: str | None) -> str:
    if path and path != "-":
        return Path(path).read_text(encoding="utf-8")
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def _get_assistant(args: argparse.Namespace) -> CodeAssistant:
    if getattr(args, "mock", False):
        return CodeAssistant(client=MockLLMClient())
    config = DevAIConfig()
    if getattr(args, "model", None):
        config.model = args.model
    return CodeAssistant(config=config)


def cmd_review(args: argparse.Namespace) -> None:
    code = _read_input(args.file)
    if not code:
        print("Error: no input provided", file=sys.stderr)
        sys.exit(1)
    assistant = _get_assistant(args)
    print(assistant.review(code, language=args.language))


def cmd_explain(args: argparse.Namespace) -> None:
    code = _read_input(args.file)
    if not code:
        print("Error: no input provided", file=sys.stderr)
        sys.exit(1)
    assistant = _get_assistant(args)
    print(assistant.explain(code, language=args.language))


def cmd_debug(args: argparse.Namespace) -> None:
    code = _read_input(args.file)
    if not code or not args.error:
        print("Error: provide code and --error", file=sys.stderr)
        sys.exit(1)
    assistant = _get_assistant(args)
    print(assistant.debug(code, args.error, language=args.language))


def cmd_commit(args: argparse.Namespace) -> None:
    diff = git_diff(staged=args.staged)
    assistant = _get_assistant(args)
    print(assistant.commit_message(diff))


def cmd_tests(args: argparse.Namespace) -> None:
    code = _read_input(args.file)
    if not code:
        print("Error: no input provided", file=sys.stderr)
        sys.exit(1)
    assistant = _get_assistant(args)
    print(assistant.generate_tests(code, framework=args.framework, language=args.language))


def cmd_security(args: argparse.Namespace) -> None:
    code = _read_input(args.file)
    if not code:
        print("Error: no input provided", file=sys.stderr)
        sys.exit(1)
    assistant = _get_assistant(args)
    print(assistant.security_review(code, language=args.language))


def cmd_refactor(args: argparse.Namespace) -> None:
    code = _read_input(args.file)
    if not code:
        print("Error: no input provided", file=sys.stderr)
        sys.exit(1)
    assistant = _get_assistant(args)
    print(assistant.refactor(code, goals=args.goals, language=args.language))


def cmd_agent(args: argparse.Namespace) -> None:
    client = MockLLMClient() if args.mock else None
    if client is None:
        from devai import LLMClient

        client = LLMClient(DevAIConfig())
    agent = CoderAgent(client=client)
    print(agent.run(args.task))


def main() -> None:
    parser = argparse.ArgumentParser(prog="devai", description="DevAI — AI tools for developers")
    parser.add_argument("--mock", action="store_true", help="Use mock LLM (no API key)")
    parser.add_argument("--model", help="LLM model name")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, handler in [
        ("review", cmd_review),
        ("explain", cmd_explain),
        ("debug", cmd_debug),
        ("commit", cmd_commit),
        ("tests", cmd_tests),
        ("security", cmd_security),
        ("refactor", cmd_refactor),
        ("agent", cmd_agent),
    ]:
        p = sub.add_parser(name)
        if name == "agent":
            p.add_argument("task", help="Task for the agent")
        elif name == "commit":
            p.add_argument("--staged", action="store_true", help="Use staged diff")
        elif name == "debug":
            p.add_argument("file", nargs="?", help="Source file")
            p.add_argument("--error", required=True, help="Error message")
        else:
            p.add_argument("file", nargs="?", help="Source file (or stdin)")
        if name in ("review", "explain", "debug", "tests", "security", "refactor"):
            p.add_argument("--language", default="python", help="Programming language")
        if name == "tests":
            p.add_argument("--framework", default="pytest", help="Test framework")
        if name == "refactor":
            p.add_argument("--goals", default="readability and maintainability")
        p.set_defaults(func=handler)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
