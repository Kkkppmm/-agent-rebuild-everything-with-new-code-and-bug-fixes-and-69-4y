"""Code utility tools for developer agents."""

import ast
import os
import re
import subprocess
from pathlib import Path
from typing import Any


def explain_code(code: str, language: str = "python") -> str:
    """Return a structural summary of code (AST-based for Python)."""
    if language == "python":
        try:
            tree = ast.parse(code)
            classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
            functions = [
                n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
            ]
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imports.append(node.module or "")
            return (
                f"Classes: {classes}\n"
                f"Functions: {functions}\n"
                f"Imports: {imports}\n"
                f"Lines: {len(code.splitlines())}"
            )
        except SyntaxError as exc:
            return f"Syntax error: {exc}"
    return f"Code ({language}): {len(code.splitlines())} lines"


def lint_python(code: str) -> dict[str, Any]:
    """Basic Python lint checks without external dependencies."""
    issues: list[dict[str, str]] = []
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return {"issues": [{"line": exc.lineno or 0, "message": str(exc.msg)}]}

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
            if not ast.get_docstring(node) and len(node.body) > 3:
                issues.append({
                    "line": node.lineno,
                    "message": f"Function '{node.name}' missing docstring",
                })
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            issues.append({
                "line": node.lineno,
                "message": "Bare except clause",
            })

    lines = code.splitlines()
    for i, line in enumerate(lines, 1):
        if len(line) > 120:
            issues.append({"line": i, "message": "Line exceeds 120 characters"})
        if re.search(r"\t", line):
            issues.append({"line": i, "message": "Contains tab character"})

    return {"issues": issues, "count": len(issues)}


def search_code(directory: str, pattern: str, file_pattern: str = "*.py") -> list[dict[str, Any]]:
    """Search for a regex pattern in files under a directory."""
    results: list[dict[str, Any]] = []
    root = Path(directory)
    if not root.exists():
        return [{"error": f"Directory not found: {directory}"}]

    regex = re.compile(pattern)
    for path in root.rglob(file_pattern):
        if path.is_file():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                for i, line in enumerate(text.splitlines(), 1):
                    if regex.search(line):
                        results.append({
                            "file": str(path),
                            "line": i,
                            "content": line.strip(),
                        })
            except OSError:
                continue
    return results


def git_diff(path: str = ".", staged: bool = False) -> str:
    """Return git diff for a path."""
    cmd = ["git", "diff"]
    if staged:
        cmd.append("--staged")
    cmd.extend(["--", path])
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=path if os.path.isdir(path) else ".",
        )
        return result.stdout or result.stderr or "No diff"
    except (subprocess.SubprocessError, FileNotFoundError) as exc:
        return f"git diff failed: {exc}"


def read_file(path: str, max_lines: int = 500) -> str:
    """Read a file with line limit."""
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        if len(lines) > max_lines:
            content = "\n".join(lines[:max_lines])
            return f"{content}\n... ({len(lines) - max_lines} more lines)"
        return "\n".join(lines)
    except OSError as exc:
        return f"Error reading file: {exc}"


def count_complexity(code: str) -> dict[str, Any]:
    """Estimate cyclomatic complexity for Python functions."""
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return {"error": str(exc)}

    complexities: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            complexity = 1
            for child in ast.walk(node):
                if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler)):
                    complexity += 1
                elif isinstance(child, ast.BoolOp):
                    complexity += len(child.values) - 1
            complexities[node.name] = complexity

    return {
        "functions": complexities,
        "max_complexity": max(complexities.values()) if complexities else 0,
        "average": (
            sum(complexities.values()) / len(complexities) if complexities else 0
        ),
    }
