"""Tests for CLI."""

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
    assert "DevAI" in result.stdout


def test_cli_review_mock():
    result = subprocess.run(
        [
            sys.executable, "-m", "devai.cli",
            "--mock", "review", "-c", "def add(a,b): return a+b",
        ],
        capture_output=True,
        text=True,
        cwd="/workspace",
        env={**__import__("os").environ, "PYTHONPATH": "/workspace/src"},
    )
    assert result.returncode == 0
    assert len(result.stdout.strip()) > 0


def test_cli_explain_mock():
    result = subprocess.run(
        [
            sys.executable, "-m", "devai.cli",
            "--mock", "explain", "-c", "x = 1",
        ],
        capture_output=True,
        text=True,
        cwd="/workspace",
        env={**__import__("os").environ, "PYTHONPATH": "/workspace/src"},
    )
    assert result.returncode == 0
