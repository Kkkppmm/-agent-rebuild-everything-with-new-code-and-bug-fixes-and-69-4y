"""Git diff utilities for DevAI."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
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


_DIFF_FENCE = re.compile(r"```(?:diff)?\n(.*?)```", re.DOTALL)


@dataclass
class PatchResult:
    """Result of applying a unified diff."""

    files_changed: list[str] = field(default_factory=list)
    applied: bool = False
    errors: list[str] = field(default_factory=list)


def extract_diff_from_text(text: str) -> str:
    """Extract a unified diff from markdown fences or raw diff text."""
    match = _DIFF_FENCE.search(text)
    if match:
        return match.group(1).strip()
    if "diff --git" in text:
        start = text.index("diff --git")
        return text[start:].strip()
    return text.strip()


def _parse_unified_diff(diff: str) -> dict[str, list[dict[str, object]]]:
    """Parse unified diff into per-file hunks."""
    files: dict[str, list[dict[str, object]]] = {}
    current_path: str | None = None
    current_hunk: dict[str, object] | None = None

    for line in diff.splitlines():
        header = _DIFF_FILE_HEADER.match(line)
        if header:
            current_path = header.group("path2")
            files.setdefault(current_path, [])
            current_hunk = None
            continue

        hunk_match = _DIFF_HUNK.match(line)
        if hunk_match and current_path is not None:
            current_hunk = {
                "old_start": int(hunk_match.group("old_start")),
                "new_start": int(hunk_match.group("new_start")),
                "lines": [],
            }
            files[current_path].append(current_hunk)
            continue

        if current_hunk is not None and line.startswith((" ", "+", "-")):
            current_hunk["lines"].append(line)

    return files


def _apply_hunks(content: str, hunks: list[dict[str, object]]) -> str:
    lines = content.splitlines(keepends=True)
    if not lines and content:
        lines = [content]
    if lines and not lines[-1].endswith("\n"):
        lines[-1] = lines[-1] + "\n"

    offset = 0
    for hunk in hunks:
        old_start = int(hunk["old_start"]) - 1 + offset
        new_lines: list[str] = []
        for raw in hunk["lines"]:
            prefix = raw[0]
            body = raw[1:]
            if prefix == " ":
                new_lines.append(body + ("\n" if not body.endswith("\n") else ""))
            elif prefix == "+":
                new_lines.append(body + ("\n" if not body.endswith("\n") else ""))
            elif prefix == "-":
                continue
        delete_count = sum(1 for raw in hunk["lines"] if raw.startswith("-"))
        insert_count = sum(1 for raw in hunk["lines"] if raw.startswith("+"))
        lines[old_start : old_start + delete_count] = new_lines
        offset += insert_count - delete_count

    return "".join(lines).rstrip("\n") + ("\n" if content.endswith("\n") else "")


def apply_unified_diff(
    diff: str,
    *,
    root: str | Path = ".",
    dry_run: bool = False,
) -> PatchResult:
    """Apply a unified diff to files under ``root``.

    Returns a :class:`PatchResult` with changed file paths and any errors.
    Set ``dry_run=True`` to validate without writing files.
    """
    parsed = _parse_unified_diff(extract_diff_from_text(diff))
    result = PatchResult()
    root_path = Path(root)

    for relative_path, hunks in parsed.items():
        file_path = root_path / relative_path
        if not file_path.exists():
            result.errors.append(f"File not found: {relative_path}")
            continue
        try:
            original = file_path.read_text(encoding="utf-8")
            updated = _apply_hunks(original, hunks)
            result.files_changed.append(relative_path)
            if not dry_run:
                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_path.write_text(updated, encoding="utf-8")
        except Exception as exc:
            result.errors.append(f"{relative_path}: {exc}")

    result.applied = bool(result.files_changed) and not result.errors
    return result
