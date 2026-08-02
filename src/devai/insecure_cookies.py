"""InsecureCookieAnalyzer — detect cookies missing security flags."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_COOKIE_METHODS = frozenset({"set_cookie", "set_signed_cookie"})


@dataclass
class InsecureCookieFinding:
    """A cookie set without recommended security flags."""

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
    """Aggregate insecure cookie statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _kw_bool(node: ast.AST) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return None


def _check_cookie_call(node: ast.Call, path: str, function: str) -> list[InsecureCookieFinding]:
    func = node.func
    if not (isinstance(func, ast.Attribute) and func.attr in _COOKIE_METHODS):
        return []

    findings: list[InsecureCookieFinding] = []
    kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}

    secure = _kw_bool(kwargs.get("secure", ast.Constant(value=False)))
    httponly = _kw_bool(kwargs.get("httponly", ast.Constant(value=False)))
    samesite = kwargs.get("samesite")

    if secure is not True:
        findings.append(
            InsecureCookieFinding(
                path=path,
                lineno=node.lineno,
                pattern="missing_secure",
                severity="high",
                message="Cookie set without secure=True — may be sent over HTTP",
                function=function,
            )
        )
    if httponly is not True:
        findings.append(
            InsecureCookieFinding(
                path=path,
                lineno=node.lineno,
                pattern="missing_httponly",
                severity="medium",
                message="Cookie set without httponly=True — accessible to JavaScript",
                function=function,
            )
        )
    if samesite is None:
        findings.append(
            InsecureCookieFinding(
                path=path,
                lineno=node.lineno,
                pattern="missing_samesite",
                severity="medium",
                message="Cookie set without samesite attribute — CSRF risk",
                function=function,
            )
        )
    elif isinstance(samesite, ast.Constant) and samesite.value in {None, "None", ""}:
        findings.append(
            InsecureCookieFinding(
                path=path,
                lineno=node.lineno,
                pattern="samesite_none",
                severity="medium",
                message="Cookie samesite is unset or None — use 'Lax' or 'Strict'",
                function=function,
            )
        )

    return findings


class _CookieVisitor(ast.NodeVisitor):
    """Walk a module AST and collect insecure cookie settings."""

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
        self.findings.extend(_check_cookie_call(node, self.path, self._current_function()))
        self.generic_visit(node)


class InsecureCookieAnalyzer:
    """Detect cookies missing secure, httponly, or samesite attributes.

    Flags Django ``response.set_cookie()``, Flask session cookies, and
    Starlette/FastAPI ``set_cookie`` calls without recommended security flags.
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
            visitor = _CookieVisitor(rel)
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
        """Return aggregate statistics."""
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
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = high * 20.0 + medium * 8.0
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
        if stats.by_pattern:
            patterns = ", ".join(f"{k}={v}" for k, v in sorted(stats.by_pattern.items()))
            lines.append(f"By pattern: {patterns}")
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
            lines.append("No insecure cookie patterns found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
