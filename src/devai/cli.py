"""Command-line interface for DevAI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from devai import __version__
from devai.agents.coder import CoderAgent
from devai.chains.simple import SimpleChain
from devai.core.client import LLMClient, MockLLMClient
from devai.core.config import DevAIConfig
from devai.pipeline import DevPipeline
from devai.prompts import dev_prompts


def _read_input(args: argparse.Namespace) -> str:
    if args.file:
        return Path(args.file).read_text(encoding="utf-8")
    if args.code:
        return args.code
    if not sys.stdin.isatty():
        return sys.stdin.read()
    print("Error: provide --file, --code, or pipe input via stdin", file=sys.stderr)
    sys.exit(1)


def _get_client(args: argparse.Namespace) -> LLMClient:
    if args.mock:
        return MockLLMClient()
    config = DevAIConfig.from_env()
    if args.model:
        config.model = args.model
    return LLMClient(config)


def cmd_review(args: argparse.Namespace) -> None:
    code = _read_input(args)
    pipeline = DevPipeline(client=_get_client(args), language=args.language)
    print(pipeline.review(code))


def cmd_explain(args: argparse.Namespace) -> None:
    code = _read_input(args)
    pipeline = DevPipeline(client=_get_client(args), language=args.language)
    print(pipeline.explain(code))


def cmd_debug(args: argparse.Namespace) -> None:
    code = _read_input(args)
    if not args.error:
        print("Error: --error is required for debug", file=sys.stderr)
        sys.exit(1)
    pipeline = DevPipeline(client=_get_client(args), language=args.language)
    print(pipeline.debug(code, args.error))


def cmd_commit(args: argparse.Namespace) -> None:
    diff = _read_input(args)
    chain = SimpleChain(client=_get_client(args), prompt=dev_prompts.COMMIT_MESSAGE)
    print(chain.run(diff=diff))


def cmd_tests(args: argparse.Namespace) -> None:
    code = _read_input(args)
    pipeline = DevPipeline(client=_get_client(args), language=args.language)
    print(pipeline.generate_tests(code, framework=args.framework))


def cmd_security(args: argparse.Namespace) -> None:
    code = _read_input(args)
    pipeline = DevPipeline(client=_get_client(args), language=args.language)
    print(pipeline.security_review(code))


def cmd_refactor(args: argparse.Namespace) -> None:
    code = _read_input(args)
    pipeline = DevPipeline(client=_get_client(args), language=args.language)
    print(pipeline.refactor(code, goals=args.goals))


def cmd_agent(args: argparse.Namespace) -> None:
    task = args.task or _read_input(args)
    agent = CoderAgent(client=_get_client(args))
    print(agent.run(task))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="devai",
        description="DevAI — Python AI library CLI for developers",
    )
    parser.add_argument("--version", action="version", version=f"devai {__version__}")
    parser.add_argument("--mock", action="store_true", help="Use mock LLM (no API key needed)")
    parser.add_argument("--model", help="Override LLM model")

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
        p = sub.add_parser(name, help=f"{name} command")
        p.add_argument("--file", "-f", help="Input file path")
        p.add_argument("--code", "-c", help="Inline code string")
        p.add_argument("--language", "-l", default="python", help="Programming language")
        if name == "debug":
            p.add_argument("--error", "-e", required=True, help="Error message")
        if name == "refactor":
            p.add_argument("--goals", default="readability and performance")
        if name == "tests":
            p.add_argument("--framework", default="pytest")
        if name == "agent":
            p.add_argument("--task", "-t", help="Task for the agent")
        p.set_defaults(func=handler)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
