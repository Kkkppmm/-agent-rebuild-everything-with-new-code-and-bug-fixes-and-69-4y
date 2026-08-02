"""InsecureSessionAnalyzer — detect insecure session and cookie configuration."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SESSION_KEYS = frozenset({
    "SECRET_KEY",
    "secret_key",
    "SESSION_COOKIE_SECURE",
    "SESSION_COOKIE_HTTPONLY",
    "SESSION_COOKIE_SAMESITE",
    "SESSION_COOKIE_NAME",
    "PERMANENT_SESSION_LIFETIME",
})
_SECRET_RE = re.compile(
    r"(secret|session|cookie|signing|key)",
    re.IGNORECASE,
)
_INSECURE_COOKIE_ATTRS = frozenset({
    "secure",
    "httponly",
    "samesite",
})


@dataclass
class InsecureSessionFinding:
    """A detected insecure session or cookie configuration."""

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
class InsecureSessionStats:
    """Aggregate insecure-session analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_false(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and node.value is False:
        return True
    if isinstance(node, ast.NameConstant) and node.value is False:
        return True
    return False


def _is_string_constant(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _key_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return node.id
    return None


def _looks_like_secret_name(name: str) -> bool:
    return bool(_SECRET_RE.search(name))


class _InsecureSessionVisitor(ast.NodeVisitor):
    """Walk a module AST and collect insecure session/cookie issues."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InsecureSessionFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(
        self,
        node: ast.AST,
        *,
        pattern: str,
        severity: str,
        message: str,
    ) -> None:
        self.findings.append(
            InsecureSessionFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
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

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            name = _key_name(target)
            if name == "SECRET_KEY" and _is_string_constant(node.value):
                value = node.value.value  # type: ignore[attr-defined]
                if isinstance(value, str) and len(value) >= 8:
                    self._add(
                        node,
                        pattern="hardcoded_secret_key",
                        severity="critical",
                        message="Hardcoded SECRET_KEY — use environment variables or a secrets manager",
                    )
            if name == "SESSION_COOKIE_SECURE" and _is_false(node.value):
                self._add(
                    node,
                    pattern="cookie_not_secure",
                    severity="high",
                    message="SESSION_COOKIE_SECURE=False allows session cookies over HTTP",
                )
            if name == "SESSION_COOKIE_HTTPONLY" and _is_false(node.value):
                self._add(
                    node,
                    pattern="cookie_not_httponly",
                    severity="high",
                    message="SESSION_COOKIE_HTTPONLY=False exposes session cookies to JavaScript",
                )
            if name and _looks_like_secret_name(name) and _is_string_constant(node.value):
                value = node.value.value  # type: ignore[attr-defined]
                if isinstance(value, str) and len(value) >= 16 and name not in {"SESSION_COOKIE_NAME"}:
                    self._add(
                        node,
                        pattern="hardcoded_session_secret",
                        severity="high",
                        message=f"Hardcoded secret in {name} — use environment variables",
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "set_cookie":
            for kw in node.keywords:
                if kw.arg == "secure" and _is_false(kw.value):
                    self._add(
                        node,
                        pattern="response_cookie_not_secure",
                        severity="high",
                        message="set_cookie(secure=False) allows cookie transmission over HTTP",
                    )
                if kw.arg == "httponly" and _is_false(kw.value):
                    self._add(
                        node,
                        pattern="response_cookie_not_httponly",
                        severity="high",
                        message="set_cookie(httponly=False) exposes cookie to client-side scripts",
                    )
                if kw.arg == "samesite" and isinstance(kw.value, ast.Constant):
                    if str(kw.value.value).lower() == "none":
                        self._add(
                            node,
                            pattern="samesite_none",
                            severity="medium",
                            message='set_cookie(samesite="none") requires secure=True and increases CSRF risk',
                        )

        if isinstance(func, ast.Attribute) and func.attr == "SessionMiddleware":
            for kw in node.keywords:
                if kw.arg == "secret_key" and _is_string_constant(kw.value):
                    self._add(
                        node,
                        pattern="hardcoded_session_secret",
                        severity="critical",
                        message="Hardcoded session secret in SessionMiddleware — use environment variables",
                    )

        self.generic_visit(node)


class InsecureSessionAnalyzer:
    """Detect insecure session and cookie configuration in web applications.

    Flags hardcoded SECRET_KEY values, disabled secure/httponly cookie flags,
    and weak session middleware settings.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[InsecureSessionFinding] = []
        self._stats: InsecureSessionStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[InsecureSessionFinding]:
        """Analyze the project and return insecure-session findings."""
        if self._findings:
            return self._findings

        findings: list[InsecureSessionFinding] = []
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
            visitor = _InsecureSessionVisitor(rel)
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

        self._stats = InsecureSessionStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> InsecureSessionStats:
        """Return aggregate insecure-session statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[InsecureSessionFinding]:
        """Return critical and high severity findings."""
        return [f for f in self.analyze() if f.severity in {"critical", "high"}]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no insecure-session issues)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        critical = sum(1 for f in self._findings if f.severity == "critical")
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = critical * 40.0 + high * 25.0 + medium * 10.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        critical = stats.by_severity.get("critical", 0)
        high = stats.by_severity.get("high", 0)
        lines = [
            f"Insecure session: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"Critical: {critical}, High: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing insecure-session findings."""
        self.analyze()
        lines = [
            "Insecure session analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No insecure session/cookie issues found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
