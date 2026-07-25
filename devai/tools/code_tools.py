"""Built-in code analysis tools for agents."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any


def explain_code(code: str, language: str = "python") -> str:
    """Summarize structure of source code (AST-based for Python)."""
    if language.lower() != "python":
        return f"Code explanation for {language} requires an LLM. Length: {len(code)} chars."

    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return f"Syntax error: {exc}"

    functions = [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            imports.extend(f"{module}.{alias.name}" if module else alias.name for alias in node.names)

    lines = len(code.splitlines())
    summary: dict[str, Any] = {
        "lines": lines,
        "functions": functions,
        "classes": classes,
        "imports": imports[:20],
    }
    parts = [
        f"Lines: {summary['lines']}",
        f"Functions ({len(functions)}): {', '.join(functions) or 'none'}",
        f"Classes ({len(classes)}): {', '.join(classes) or 'none'}",
        f"Imports ({len(imports)}): {', '.join(imports[:10]) or 'none'}",
    ]
    return "\n".join(parts)


def lint_python(code: str) -> str:
    """Basic static checks on Python source code."""
    issues: list[str] = []
    try:
        ast.parse(code)
    except SyntaxError as exc:
        return f"SYNTAX ERROR at line {exc.lineno}: {exc.msg}"

    lines = code.splitlines()
    for i, line in enumerate(lines, 1):
        if len(line) > 120:
            issues.append(f"Line {i}: exceeds 120 characters ({len(line)})")
        if "\t" in line:
            issues.append(f"Line {i}: contains tab character")
        if line.rstrip() != line:
            issues.append(f"Line {i}: trailing whitespace")

    tree = ast.parse(code)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if not node.body:
                issues.append(f"Line {node.lineno}: empty function '{node.name}'")
            elif not ast.get_docstring(node) and not node.name.startswith("_"):
                issues.append(f"Line {node.lineno}: public function '{node.name}' missing docstring")

    if not issues:
        return "No issues found."
    return "\n".join(issues)


def search_code(directory: str, pattern: str, file_glob: str = "*.py") -> str:
    """Search for a regex pattern in files under a directory."""
    root = Path(directory)
    if not root.is_dir():
        return f"Directory not found: {directory}"

    regex = re.compile(pattern)
    matches: list[str] = []
    for path in root.rglob(file_glob):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            if regex.search(line):
                rel = path.relative_to(root)
                matches.append(f"{rel}:{line_no}: {line.strip()[:120]}")
                if len(matches) >= 50:
                    return "\n".join(matches) + "\n... (truncated at 50 matches)"

    if not matches:
        return f"No matches for '{pattern}' in {directory}"
    return "\n".join(matches)
