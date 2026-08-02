"""InsecureCookieAnalyzer — detect cookies missing security flags."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SET_COOKIE_RE = re.compile(
    r"(set_cookie|setCookie|Set-Cookie|response\.set_cookie|"
    r"make_response.*set_cookie)",
    re.IGNORECASE,
)


@dataclass
class InsecureCookieFinding:
    """A detected insecure cookie configuration."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class InsecureCookieStats:
    """Aggregate insecure cookie analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = []
        current: ast.AST = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _kw_bool(kw: ast.keyword, expected: bool) -> bool | None:
    if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, bool):
        return kw.value.value == expected
    return None


class _InsecureCookieVisitor(ast.NodeVisitor):
    """Walk a module AST and collect insecure cookie patterns."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InsecureCookieFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(self, lineno: int, pattern: str, severity: str, message: str) -> None:
        self.findings.append(
            InsecureCookieFinding(
                path=self.path,
                lineno=lineno,
                pattern=pattern,
                severity=severity,
                message=message,
                function=self._current_function(),
            )
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        short = name.split(".")[-1] if name else ""

        if short == "set_cookie":
            has_secure = False
            has_httponly = False
            has_samesite = False

            for kw in node.keywords:
                if kw.arg == "secure" and _kw_bool(kw, True):
                    has_secure = True
                if kw.arg == "httponly" and _kw_bool(kw, True):
                    has_httponly = True
                if kw.arg == "samesite" and isinstance(kw.value, ast.Constant):
                    if kw.value.value and kw.value.value != "None":
                        has_samesite = True

            if not has_secure:
                self._add(
                    node.lineno,
                    "missing_secure",
                    "medium",
                    "Cookie set without secure=True — may be sent over HTTP",
                )
            if not has_httponly:
                self._add(
                    node.lineno,
                    "missing_httponly",
                    "medium",
                    "Cookie set without httponly=True — accessible to JavaScript",
                )
            if not has_samesite:
                self._add(
                    node.lineno,
                    "missing_samesite",
                    "low",
                    "Cookie set without samesite — vulnerable to CSRF",
                )

        self.generic_visit(node)


class InsecureCookieAnalyzer:
    """Detect cookies missing security flags.

    Flags ``set_cookie()`` calls missing ``secure``, ``httponly``, or ``samesite``
    attributes in Flask, Django, and FastAPI applications.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
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
        """Analyze the project and return insecure cookie findings."""
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

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

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
        """Return aggregate insecure cookie statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[InsecureCookieFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no insecure cookies)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = medium * 8.0 + low * 3.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        lines = [
            f"Insecure cookies: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing insecure cookie findings."""
        self.analyze()
        lines = [
            "Insecure cookie analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No insecure cookie configurations found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
