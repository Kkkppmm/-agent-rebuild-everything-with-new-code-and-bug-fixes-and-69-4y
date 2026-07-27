"""Code utility tools for DevAI agents."""

from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path


def explain_code(code: str, language: str = "python") -> str:
    """Provide a structural explanation of code without an LLM."""
    if language == "python":
        try:
            tree = ast.parse(code)
            functions = [
                node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
            ]
            classes = [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.append(node.module)
            lines = [f"Lines: {code.count(chr(10)) + 1}"]
            if functions:
                lines.append(f"Functions: {', '.join(functions)}")
            if classes:
                lines.append(f"Classes: {', '.join(classes)}")
            if imports:
                lines.append(f"Imports: {', '.join(imports)}")
            return "\n".join(lines)
        except SyntaxError as e:
            return f"Syntax error: {e}"
    return f"Code ({language}): {len(code)} characters, {code.count(chr(10)) + 1} lines"


def lint_python(code: str) -> str:
    """Run basic Python lint checks using AST."""
    issues: list[str] = []
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return f"Syntax error on line {e.lineno}: {e.msg}"

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if not node.body:
                issues.append(f"Empty function: {node.name}")
            if not ast.get_docstring(node) and not node.name.startswith("_"):
                issues.append(f"Missing docstring: {node.name}")
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            issues.append(f"Bare except on line {node.lineno}")

    lines = code.split("\n")
    for i, line in enumerate(lines, 1):
        if len(line) > 120:
            issues.append(f"Line {i} exceeds 120 characters")
        if re.search(r"\bprint\(", line) and "test" not in line.lower():
            issues.append(f"Line {i}: print statement found")

    return "\n".join(issues) if issues else "No issues found."


def search_code(pattern: str, directory: str = ".", file_pattern: str = "*.py") -> str:
    """Search for a regex pattern in code files."""
    results: list[str] = []
    root = Path(directory)
    if not root.exists():
        return f"Directory not found: {directory}"

    try:
        compiled = re.compile(pattern)
    except re.error as e:
        return f"Invalid regex: {e}"

    for path in root.rglob(file_pattern):
        if any(part.startswith(".") for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            for i, line in enumerate(text.split("\n"), 1):
                if compiled.search(line):
                    results.append(f"{path}:{i}: {line.strip()}")
        except (OSError, UnicodeDecodeError):
            continue

    if not results:
        return f"No matches for '{pattern}'"
    return "\n".join(results[:50])


def git_diff(staged: bool = False, path: str | None = None) -> str:
    """Get git diff output."""
    cmd = ["git", "diff"]
    if staged:
        cmd.append("--staged")
    if path:
        cmd.extend(["--", path])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout or "No changes."
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return f"Git diff failed: {e}"


def read_file(path: str, max_lines: int = 500) -> str:
    """Read a file's contents."""
    try:
        p = Path(path)
        if not p.exists():
            return f"File not found: {path}"
        lines = p.read_text(encoding="utf-8", errors="replace").split("\n")
        if len(lines) > max_lines:
            content = "\n".join(lines[:max_lines])
            return f"{content}\n... [{len(lines) - max_lines} more lines]"
        return "\n".join(lines)
    except OSError as e:
        return f"Error reading file: {e}"


def count_complexity(code: str) -> str:
    """Calculate cyclomatic complexity for Python code."""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return f"Syntax error: {e}"

    complexities: dict[str, int] = {}

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            complexity = 1
            for child in ast.walk(node):
                if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                    complexity += 1
                elif isinstance(child, ast.BoolOp):
                    complexity += len(child.values) - 1
            complexities[node.name] = complexity

    if not complexities:
        return "No functions found."

    lines = [f"{name}: complexity {score}" for name, score in complexities.items()]
    avg = sum(complexities.values()) / len(complexities)
    lines.append(f"Average complexity: {avg:.1f}")
    return "\n".join(lines)


def list_files(directory: str = ".", pattern: str = "*") -> str:
    """List files in a directory."""
    root = Path(directory)
    if not root.exists():
        return f"Directory not found: {directory}"

    files = sorted(
        str(p.relative_to(root))
        for p in root.rglob(pattern)
        if p.is_file() and not any(part.startswith(".") for part in p.parts)
    )
    if not files:
        return f"No files matching '{pattern}' in {directory}"
    return "\n".join(files[:100])
