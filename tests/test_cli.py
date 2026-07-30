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

    def test_diff_args(self):
        parser = build_parser()
        args = parser.parse_args(["--mock", "diff"])
        assert args.command == "diff"

    def test_performance_args(self):
        parser = build_parser()
        args = parser.parse_args(["--mock", "performance", "def slow(): pass"])
        assert args.command == "performance"

    def test_migrate_args(self):
        parser = build_parser()
        args = parser.parse_args([
            "--mock",
            "migrate",
            "code",
            "--source",
            "v1",
            "--target",
            "v2",
        ])
        assert args.source == "v1"
        assert args.target == "v2"

    def test_run_args(self):
        parser = build_parser()
        args = parser.parse_args([
            "--mock",
            "run",
            "program.json",
            "--code",
            "def foo(): pass",
            "--context",
            "env=prod",
        ])
        assert args.command == "run"
        assert args.program == "program.json"
        assert args.context == ["env=prod"]

    def test_presets_args(self):
        parser = build_parser()
        args = parser.parse_args(["presets"])
        assert args.command == "presets"

    def test_kit_args(self):
        parser = build_parser()
        args = parser.parse_args(["--mock", "kit", "audit", "def foo(): pass"])
        assert args.command == "kit"
        assert args.workflow == "audit"

    def test_batch_review_args(self):
        parser = build_parser()
        args = parser.parse_args(
            ["--mock", "batch-review", "-d", "src", "--pattern", "*.py", "--markdown"]
        )
        assert args.command == "batch-review"
        assert args.directory == "src"
        assert args.pattern == "*.py"
        assert args.markdown is True

    def test_extract_blocks_args(self):
        parser = build_parser()
        args = parser.parse_args(
            ["extract-blocks", "response.md", "--first", "--language", "python"]
        )
        assert args.command == "extract-blocks"
        assert args.first is True
        assert args.language == "python"

    def test_init_args(self):
        parser = build_parser()
        args = parser.parse_args(["init", "./my-app", "--provider", "ollama", "--force"])
        assert args.command == "init"
        assert args.path == "./my-app"
        assert args.provider == "ollama"
        assert args.force is True
