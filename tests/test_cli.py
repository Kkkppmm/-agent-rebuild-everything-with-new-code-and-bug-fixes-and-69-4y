"""Tests for DevAI CLI."""

from unittest.mock import patch

import pytest

from devai.cli import _read_input, build_parser, main


class TestCLI:
    def test_parser_help(self):
        parser = build_parser()
        assert parser.prog == "devai"

    def test_parser_subcommands(self):
        parser = build_parser()
        args = parser.parse_args(["--mock", "review", "def foo(): pass"])
        assert args.command == "review"
        assert args.mock is True

    def test_read_input_file(self, tmp_path):
        f = tmp_path / "code.py"
        f.write_text("x = 1")
        assert _read_input(str(f)) == "x = 1"

    def test_read_input_string(self):
        assert _read_input("def foo(): pass") == "def foo(): pass"

    @patch("devai.cli.cmd_review")
    def test_main_review(self, mock_cmd):
        main(["--mock", "review", "code"])
        mock_cmd.assert_called_once()

    def test_no_command_exits(self):
        with pytest.raises(SystemExit):
            main([])

    def test_debug_args(self):
        parser = build_parser()
        args = parser.parse_args([
            "--mock", "debug", "--code", "x=1", "--error", "NameError"
        ])
        assert args.command == "debug"
        assert args.error == "NameError"

    def test_agent_args(self):
        parser = build_parser()
        args = parser.parse_args(["--mock", "agent", "find bugs"])
        assert args.task == "find bugs"
