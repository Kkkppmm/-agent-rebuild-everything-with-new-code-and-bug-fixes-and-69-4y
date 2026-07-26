"""Tests for CLI."""

from unittest.mock import patch

from devai.cli import main


def test_cli_review_mock(capsys):
    with patch("sys.argv", ["devai", "--mock", "review", "--code", "x=1"]):
        main()
    captured = capsys.readouterr()
    assert "Mock response" in captured.out


def test_cli_explain_local(capsys):
    with patch(
        "sys.argv",
        ["devai", "--mock", "explain", "--code", "def foo(): pass", "--local-only"],
    ):
        main()
    captured = capsys.readouterr()
    assert "foo" in captured.out
