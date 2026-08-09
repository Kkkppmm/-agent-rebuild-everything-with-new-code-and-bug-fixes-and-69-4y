"""InsecureCookieAnalyzer — detect missing secure/httponly cookie flags."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_COOKIE_CALLS = frozenset({"set_cookie", "setCookie", "set"})
_RESPONSE_ATTRS = frozenset({"set_cookie", "cookies"})
_INSECURE_PATTERNS = [
    re.compile(r"set_cookie\s*\([^)]*\)", re.IGNORECASE),
    re.compile(r"response\.cookies\.set\s*\(", re.IGNORECASE),
]


@dataclass
class InsecureCookieFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class InsecureCookieStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _has_secure_flags(node: ast.Call) -> bool:
    kw_names = {kw.arg for kw in node.keywords if kw.arg}
    if "secure" in kw_names and "httponly" in kw_names:
        return True
    if "samesite" in kw_names:
        return True
    return False


def _is_cookie_call(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Attribute):
        if node.func.attr in _COOKIE_CALLS:
            if isinstance(node.func.value, ast.Attribute) and node.func.value.attr == "cookies":
                return True
            if node.func.attr == "set_cookie":
                return True
    return False


class _InsecureCookieVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InsecureCookieFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        if _is_cookie_call(node) and not _has_secure_flags(node):
            self.findings.append(
                InsecureCookieFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern="missing_flags",
                    severity="medium",
                    message="Cookie set without secure/httponly/samesite flags",
                    function=self._current_function(),
                )
            )
        self.generic_visit(node)


class InsecureCookieAnalyzer:
    """Detect cookies set without secure, httponly, or samesite attributes."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureCookieFinding] = []
        self._stats: InsecureCookieStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[InsecureCookieFinding]:
        if self._findings:
            return self._findings

        findings: list[InsecureCookieFinding] = []
        files_scanned = 0
        files_with_findings: set[str] = set()

        for path in sorted(self.root.rglob("*.py")):
            if not path.is_file() or self._should_skip(path):
                continue
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except (OSError, UnicodeDecodeError, SyntaxError):
                continue

            files_scanned += 1
            rel = str(path.relative_to(self.root))
            visitor = _InsecureCookieVisitor(rel)
            visitor.visit(tree)
            if visitor.findings:
                files_with_findings.add(rel)
            findings.extend(visitor.findings)

        self._findings = findings
        self._files_scanned = files_scanned
        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = InsecureCookieStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureCookieStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = medium * 10.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Insecure cookies: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Insecure cookie analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No insecure cookie patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
