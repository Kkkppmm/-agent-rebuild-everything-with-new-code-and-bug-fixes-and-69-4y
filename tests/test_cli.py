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


def test_cli_mock_review():
    result = subprocess.run(
        [sys.executable, "-m", "devai.cli", "--mock", "review", "--code", "x=1"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert len(result.stdout) > 0
