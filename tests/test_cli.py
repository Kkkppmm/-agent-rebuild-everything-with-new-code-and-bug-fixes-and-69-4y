"""Tests for CLI."""

import sys
from io import StringIO
from unittest.mock import patch

from devai.cli import build_parser, main


def test_build_parser():
  parser = build_parser()
  args = parser.parse_args(["--mock", "review", "file.py"])
  assert args.mock is True
  assert args.command == "review"
  assert args.path == "file.py"


def test_cli_review_mock(capsys):
  with patch.object(sys, "argv", ["devai", "--mock", "review"]), patch("sys.stdin", StringIO("def add(a,b): return a+b")):
    result = main(["--mock", "review"])
  assert result == 0
  captured = capsys.readouterr()
  assert captured.out.strip() != ""


def test_cli_explain_mock(capsys):
  result = main(["--mock", "explain", "def foo(): pass"])
  assert result == 0


def test_cli_agent_mock(capsys):
  result = main(["--mock", "agent", "list files"])
  assert result == 0
