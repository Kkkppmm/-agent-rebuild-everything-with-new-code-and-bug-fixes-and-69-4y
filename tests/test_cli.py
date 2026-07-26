"""Tests for CLI."""

import subprocess
import sys


def test_cli_help():
    result = subprocess.run(
        [sys.executable, "-m", "devai.cli", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "DevAI" in result.stdout


def test_cli_review_mock():
    result = subprocess.run(
        [sys.executable, "-m", "devai.cli", "--mock", "review"],
        input="def foo(): pass",
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert len(result.stdout) > 0


def test_cli_explain_mock():
    result = subprocess.run(
        [sys.executable, "-m", "devai.cli", "--mock", "explain", "x = 1"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0


def test_cli_commit_mock():
    result = subprocess.run(
        [sys.executable, "-m", "devai.cli", "--mock", "commit"],
        input="+ def new(): pass",
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
