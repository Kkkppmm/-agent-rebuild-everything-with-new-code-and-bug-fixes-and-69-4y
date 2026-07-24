"""Tests for CLI."""

import argparse
from unittest.mock import patch

from devai.cli import build_parser, cmd_explain, cmd_review, main


def test_build_parser_has_commands():
    parser = build_parser()
    args = parser.parse_args(["review", "foo.py"])
    assert args.command == "review"
    assert args.file == "foo.py"


def test_build_parser_explain():
    parser = build_parser()
    args = parser.parse_args(["explain", "def foo(): pass"])
    assert args.command == "explain"


def test_build_parser_commit():
    parser = build_parser()
    args = parser.parse_args(["commit", "--staged"])
    assert args.staged is True


def test_cmd_review(tmp_path):
    f = tmp_path / "test.py"
    f.write_text("def foo(): pass")
    args = argparse.Namespace(file=str(f), language="python")
    with patch("sys.stdout"):
        cmd_review(args)


def test_cmd_explain_code():
    args = argparse.Namespace(code="x=1", file=None, language="python")
    with patch("sys.stdout"):
        cmd_explain(args)


def test_main_review(tmp_path):
    f = tmp_path / "code.py"
    f.write_text("pass")
    with patch("sys.argv", ["devai", "review", str(f)]):
        with patch("sys.stdout"):
            main()
