"""Tests for DevAI CLI."""

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
        [sys.executable, "-m", "devai.cli", "--mock", "review", "--code", "def foo(): pass"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert len(result.stdout) > 0


def test_cli_explain_mock():
    result = subprocess.run(
        [sys.executable, "-m", "devai.cli", "--mock", "explain", "--code", "x = 1"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0


def test_cli_agent_mock():
    result = subprocess.run(
        [sys.executable, "-m", "devai.cli", "--mock", "agent", "--task", "hello"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0


def test_cli_docstring_mock():
    result = subprocess.run(
        [sys.executable, "-m", "devai.cli", "--mock", "docstring", "--code", "def foo(): pass"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert len(result.stdout) > 0


def test_cli_pr_mock():
    result = subprocess.run(
        [sys.executable, "-m", "devai.cli", "--mock", "pr", "--diff", "diff --git a/foo"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0


def test_cli_changelog_mock():
    result = subprocess.run(
        [sys.executable, "-m", "devai.cli", "--mock", "changelog", "--changes", "feat: add cache"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
