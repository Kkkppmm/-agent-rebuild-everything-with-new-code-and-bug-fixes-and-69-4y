"""Command-line interface for DevAI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from devai import CodeAssistant, DevAIConfig, LLMClient, MockLLMClient


def _get_client(use_mock: bool) -> LLMClient | MockLLMClient:
  if use_mock:
    return MockLLMClient()
  config = DevAIConfig.from_env()
  if not config.api_key:
    print("Warning: No API key found. Using mock client. Set OPENAI_API_KEY or use --mock.", file=sys.stderr)
    return MockLLMClient()
  return LLMClient(config=config)


def _read_input(path: str | None) -> str:
  if path:
    return Path(path).read_text(encoding="utf-8", errors="replace")
  return sys.stdin.read()


def cmd_review(args: argparse.Namespace) -> int:
  client = _get_client(args.mock)
  assistant = CodeAssistant(client=client)
  if args.path and Path(args.path).is_dir():
    print(assistant.review_directory(args.path))
  elif args.path:
    print(assistant.review_file(args.path))
  else:
    code = _read_input(None)
    print(assistant.review(code))
  return 0


def cmd_explain(args: argparse.Namespace) -> int:
  client = _get_client(args.mock)
  assistant = CodeAssistant(client=client)
  code = args.code or _read_input(args.file)
  print(assistant.explain(code))
  return 0


def cmd_debug(args: argparse.Namespace) -> int:
  client = _get_client(args.mock)
  assistant = CodeAssistant(client=client)
  code = args.code or _read_input(args.file)
  print(assistant.debug(args.error, code))
  return 0


def cmd_commit(args: argparse.Namespace) -> int:
  client = _get_client(args.mock)
  assistant = CodeAssistant(client=client)
  from devai.tools import git_diff
  diff = git_diff(args.path or ".", staged=args.staged)
  print(assistant.commit_message(diff))
  return 0


def cmd_tests(args: argparse.Namespace) -> int:
  client = _get_client(args.mock)
  assistant = CodeAssistant(client=client)
  code = _read_input(args.file) if args.file else Path(args.path).read_text()
  print(assistant.generate_tests(code, framework=args.framework))
  return 0


def cmd_security(args: argparse.Namespace) -> int:
  client = _get_client(args.mock)
  assistant = CodeAssistant(client=client)
  if args.path and Path(args.path).is_file():
    code = Path(args.path).read_text()
  else:
    code = _read_input(args.file)
  print(assistant.security_audit(code))
  return 0


def cmd_refactor(args: argparse.Namespace) -> int:
  client = _get_client(args.mock)
  assistant = CodeAssistant(client=client)
  code = _read_input(args.file) if args.file else Path(args.path).read_text()
  print(assistant.refactor(code, goal=args.goal))
  return 0


def cmd_docstring(args: argparse.Namespace) -> int:
  client = _get_client(args.mock)
  assistant = CodeAssistant(client=client)
  code = _read_input(args.file) if args.file else Path(args.path).read_text()
  print(assistant.generate_docstrings(code, style=args.style))
  return 0


def cmd_agent(args: argparse.Namespace) -> int:
  from devai.agents import CoderAgent
  from devai.tools import ToolRegistry

  client = _get_client(args.mock)
  agent = CoderAgent(client=client, tools=ToolRegistry.default())
  print(agent.run(args.task))
  return 0


def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(prog="devai", description="DevAI — AI tools for developers")
  parser.add_argument("--mock", action="store_true", help="Use mock LLM (no API key needed)")
  sub = parser.add_subparsers(dest="command", required=True)

  p = sub.add_parser("review", help="Review code")
  p.add_argument("path", nargs="?", help="File or directory to review")
  p.set_defaults(func=cmd_review)

  p = sub.add_parser("explain", help="Explain code")
  p.add_argument("code", nargs="?", help="Code to explain")
  p.add_argument("-f", "--file", help="Read code from file")
  p.set_defaults(func=cmd_explain)

  p = sub.add_parser("debug", help="Debug an error")
  p.add_argument("--error", "-e", required=True, help="Error message")
  p.add_argument("--code", "-c", help="Code with the error")
  p.add_argument("-f", "--file", help="Read code from file")
  p.set_defaults(func=cmd_debug)

  p = sub.add_parser("commit", help="Generate commit message from diff")
  p.add_argument("path", nargs="?", default=".", help="Path for git diff")
  p.add_argument("--staged", action="store_true", help="Use staged changes")
  p.set_defaults(func=cmd_commit)

  p = sub.add_parser("tests", help="Generate tests")
  p.add_argument("path", help="File to generate tests for")
  p.add_argument("-f", "--file", help="Alternative file input")
  p.add_argument("--framework", default="pytest", help="Test framework")
  p.set_defaults(func=cmd_tests)

  p = sub.add_parser("security", help="Security audit")
  p.add_argument("path", nargs="?", help="File to audit")
  p.add_argument("-f", "--file", help="Read from file/stdin")
  p.set_defaults(func=cmd_security)

  p = sub.add_parser("refactor", help="Refactor code")
  p.add_argument("path", help="File to refactor")
  p.add_argument("-f", "--file", help="Alternative file input")
  p.add_argument("--goal", default="improve readability", help="Refactoring goal")
  p.set_defaults(func=cmd_refactor)

  p = sub.add_parser("docstring", help="Generate docstrings")
  p.add_argument("path", help="File to add docstrings to")
  p.add_argument("-f", "--file", help="Alternative file input")
  p.add_argument("--style", default="Google", help="Docstring style")
  p.set_defaults(func=cmd_docstring)

  p = sub.add_parser("agent", help="Run coding agent")
  p.add_argument("task", help="Task for the agent")
  p.set_defaults(func=cmd_agent)

  return parser


def main(argv: list[str] | None = None) -> int:
  parser = build_parser()
  args = parser.parse_args(argv)
  return args.func(args)


if __name__ == "__main__":
  sys.exit(main())
