"""DevAI command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from devai import CodeAssistant, DevAIConfig
from devai.agents import CoderAgent
from devai.core import LLMClient, MockLLMClient


def _get_client(args: argparse.Namespace):
  if args.mock:
    return MockLLMClient()
  config = DevAIConfig.from_env()
  if args.model:
    config.model = args.model
  return LLMClient(config)


def cmd_review(args: argparse.Namespace) -> None:
  code = Path(args.file).read_text() if args.file else args.code
  if not code:
    print("Error: provide --file or --code", file=sys.stderr)
    sys.exit(1)
  assistant = CodeAssistant(client=_get_client(args))
  print(assistant.review(code, language=args.language))


def cmd_explain(args: argparse.Namespace) -> None:
  code = Path(args.file).read_text() if args.file else args.code
  assistant = CodeAssistant(client=_get_client(args))
  print(assistant.explain(code, language=args.language))


def cmd_debug(args: argparse.Namespace) -> None:
  code = Path(args.file).read_text() if args.file else args.code
  assistant = CodeAssistant(client=_get_client(args))
  print(assistant.debug(code, args.error, language=args.language))


def cmd_commit(args: argparse.Namespace) -> None:
  from devai.tools import git_diff

  diff = git_diff(staged=args.staged)
  assistant = CodeAssistant(client=_get_client(args))
  print(assistant.commit_message(diff))


def cmd_tests(args: argparse.Namespace) -> None:
  code = Path(args.file).read_text()
  assistant = CodeAssistant(client=_get_client(args))
  print(assistant.generate_tests(code, language=args.language))


def cmd_security(args: argparse.Namespace) -> None:
  code = Path(args.file).read_text()
  assistant = CodeAssistant(client=_get_client(args))
  print(assistant.security_review(code, language=args.language))


def cmd_refactor(args: argparse.Namespace) -> None:
  code = Path(args.file).read_text()
  assistant = CodeAssistant(client=_get_client(args))
  print(assistant.refactor(code, language=args.language))


def cmd_agent(args: argparse.Namespace) -> None:
  agent = CoderAgent(client=_get_client(args))
  print(agent.run(args.task))


def main() -> None:
  parser = argparse.ArgumentParser(
    prog="devai",
    description="DevAI — AI tools for developers",
  )
  parser.add_argument("--mock", action="store_true", help="Use mock client (no API key)")
  parser.add_argument("--model", help="Override model name")
  sub = parser.add_subparsers(dest="command", required=True)

  review = sub.add_parser("review", help="Review code")
  review.add_argument("file", nargs="?", help="File to review")
  review.add_argument("--code", help="Inline code string")
  review.add_argument("--language", default="python")
  review.set_defaults(func=cmd_review)

  explain = sub.add_parser("explain", help="Explain code")
  explain.add_argument("file", nargs="?", help="File to explain")
  explain.add_argument("--code", help="Inline code string")
  explain.add_argument("--language", default="python")
  explain.set_defaults(func=cmd_explain)

  debug = sub.add_parser("debug", help="Debug code with an error")
  debug.add_argument("file", nargs="?", help="File to debug")
  debug.add_argument("--code", help="Inline code string")
  debug.add_argument("--error", required=True, help="Error message")
  debug.add_argument("--language", default="python")
  debug.set_defaults(func=cmd_debug)

  commit = sub.add_parser("commit", help="Generate commit message from diff")
  commit.add_argument("--staged", action="store_true")
  commit.set_defaults(func=cmd_commit)

  tests = sub.add_parser("tests", help="Generate tests for a file")
  tests.add_argument("file")
  tests.add_argument("--language", default="python")
  tests.set_defaults(func=cmd_tests)

  security = sub.add_parser("security", help="Security review")
  security.add_argument("file")
  security.add_argument("--language", default="python")
  security.set_defaults(func=cmd_security)

  refactor = sub.add_parser("refactor", help="Refactor code")
  refactor.add_argument("file")
  refactor.add_argument("--language", default="python")
  refactor.set_defaults(func=cmd_refactor)

  agent = sub.add_parser("agent", help="Run coding agent")
  agent.add_argument("task", help="Task description")
  agent.set_defaults(func=cmd_agent)

  args = parser.parse_args()
  args.func(args)


if __name__ == "__main__":
  main()
