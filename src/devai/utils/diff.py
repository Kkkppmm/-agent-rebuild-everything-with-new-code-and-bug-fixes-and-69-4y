"""Git diff utilities for DevAI."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path


_DIFF_FILE_HEADER = re.compile(r"^diff --git a/(?P<path>.+?) b/(?P<path2>.+)$")
_DIFF_HUNK = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,\d+)? \+(?P<new_start>\d+)(?:,\d+)? @@",
    re.MULTILINE,
)


def get_git_diff(
    staged: bool = False,
    base: str | None = None,
    path: str | None = None,
) -> str:
    """Return git diff output for the current repository."""
    cmd = ["git", "diff"]
    if staged:
        cmd.append("--cached")
    if base:
        cmd.append(base)
    if path:
        cmd.append("--")
        cmd.append(path)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:
        raise RuntimeError("git is not installed or not on PATH") from exc
    if result.returncode != 0 and not result.stdout:
        raise RuntimeError(result.stderr.strip() or "git diff failed")
    return result.stdout


def parse_changed_files(diff: str) -> list[str]:
    """Extract changed file paths from a unified diff."""
    files: list[str] = []
    seen: set[str] = set()
    for line in diff.splitlines():
        match = _DIFF_FILE_HEADER.match(line)
        if not match:
            continue
        path = match.group("path2")
        if path not in seen:
            seen.add(path)
            files.append(path)
    return files


def summarize_diff(diff: str) -> dict[str, int | list[str]]:
    """Summarize additions, deletions, and changed files in a diff."""
    additions = 0
    deletions = 0
    for line in diff.splitlines():
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            additions += 1
        elif line.startswith("-"):
            deletions += 1
    return {
        "files": parse_changed_files(diff),
        "additions": additions,
        "deletions": deletions,
        "hunks": len(_DIFF_HUNK.findall(diff)),
    }


def read_diff(path: str) -> str:
    """Read diff content from a file path."""
    return Path(path).read_text(encoding="utf-8", errors="replace")
