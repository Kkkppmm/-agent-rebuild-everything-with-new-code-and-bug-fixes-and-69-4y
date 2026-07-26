"""Tests for CLI module."""

import subprocess
import sys


def test_cli_version():
    result = subprocess.run(
        [sys.executable, "-m", "devai.cli", "--version"],
        capture_output=True,
        text=True,
        cwd="/workspace",
        env={**__import__("os").environ, "PYTHONPATH": "/workspace/src"},
    )
    assert result.returncode == 0
    assert "0.4.0" in result.stdout


def test_cli_review_mock():
    result = subprocess.run(
        [
            sys.executable, "-m", "devai.cli",
            "--mock", "review", "--code", "x = 1",
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
            "--mock", "explain", "--code", "def f(): pass",
        ],
        capture_output=True,
        text=True,
        cwd="/workspace",
        env={**__import__("os").environ, "PYTHONPATH": "/workspace/src"},
    )
    assert result.returncode == 0
