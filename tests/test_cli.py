"""Tests for the DevAI CLI."""

from unittest.mock import MagicMock, patch

from devai.cli import build_parser, _detect_language


class TestCLI:
    def test_parser_has_commands(self):
        parser = build_parser()
        assert parser.parse_args(["review", "main.py"])
        assert parser.parse_args(["explain", "main.py"])
        assert parser.parse_args(["commit"])
        assert parser.parse_args(["security", "app.py"])

    def test_detect_language(self):
        assert _detect_language("app.py") == "python"
        assert _detect_language("app.ts") == "typescript"
        assert _detect_language("app.unknown") == "text"

    @patch("devai.cli._run_chain", return_value=0)
    @patch("devai.cli.read_file", return_value="def foo(): pass")
    def test_cmd_review(self, mock_read, mock_run):
        from devai.cli import cmd_review

        args = MagicMock()
        args.file = "main.py"
        assert cmd_review(args) == 0
        mock_run.assert_called_once()

    @patch("devai.cli.git_diff", return_value="diff content")
    @patch("devai.cli._run_chain", return_value=0)
    def test_cmd_commit(self, mock_run, mock_diff):
        from devai.cli import cmd_commit

        args = MagicMock()
        args.staged = False
        assert cmd_commit(args) == 0
