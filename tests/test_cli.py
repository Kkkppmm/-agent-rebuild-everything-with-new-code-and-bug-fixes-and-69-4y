"""Tests for DevAI CLI."""

import subprocess
import sys


def test_cli_help():
    result = subprocess.run(
        [sys.executable, "-m", "devai.cli", "--help"],
        capture_output=True,
        text=True,
        cwd="/workspace",
        env={**__import__("os").environ, "PYTHONPATH": "/workspace/src"},
    )
    assert result.returncode == 0
    assert "review" in result.stdout


def test_cli_mock_review():
    result = subprocess.run(
        [
            sys.executable, "-m", "devai.cli",
            "--mock", "review",
            "--code", "def add(a, b): return a + b",
        ],
        capture_output=True,
        text=True,
        cwd="/workspace",
        env={**__import__("os").environ, "PYTHONPATH": "/workspace/src"},
    )
    assert result.returncode == 0
    assert result.stdout.strip()
