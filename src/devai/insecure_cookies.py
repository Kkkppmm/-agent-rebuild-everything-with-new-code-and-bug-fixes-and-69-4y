"""InsecureCookieAnalyzer — detect cookies set without security flags."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_COOKIE_METHODS = frozenset({"set_cookie", "set_signed_cookie"})
_SECURITY_KWARGS = frozenset({"secure", "httponly", "samesite"})


@dataclass
class InsecureCookieFinding:
    """A cookie set without recommended security flags."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    missing_flags: list[str] = field(default_factory=list)
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        flags = ", ".join(self.missing_flags) if self.missing_flags else "security flags"
        return f"{loc}{fn} [{self.severity}] {self.pattern}: missing {flags} — {self.message}"


@dataclass
class InsecureCookieStats:
    """Aggregate insecure cookie analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _kwarg_names(call: ast.Call) -> set[str]:
    names: set[str] = set()
    for kw in call.keywords:
        if kw.arg is not None:
            names.add(kw.arg)
    return names


def _kwarg_is_false(call: ast.Call, name: str) -> bool:
    for kw in call.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is False:
            return True
    return False


def _classify_set_cookie(node: ast.Call) -> tuple[str, str, str, list[str]] | None:
    func = node.func
    method = None
    if isinstance(func, ast.Attribute) and func.attr in _COOKIE_METHODS:
        method = func.attr
    if method is None:
        return None

    kwargs = _kwarg_names(node)
    missing: list[str] = []
    if "secure" not in kwargs or _kwarg_is_false(node, "secure"):
        missing.append("secure")
    if "httponly" not in kwargs or _kwarg_is_false(node, "httponly"):
        missing.append("httponly")
    if "samesite" not in kwargs:
        missing.append("samesite")

    if not missing:
        return None

    severity = "high" if "secure" in missing or "httponly" in missing else "medium"
    return (
        method,
        severity,
        "Set cookies with secure=True, httponly=True, and samesite='Lax' or 'Strict'",
        missing,
    )


class _InsecureCookieVisitor(ast.NodeVisitor):
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
        result = _classify_set_cookie(node)
        if result:
            pattern, severity, message, missing = result
            self.findings.append(
                InsecureCookieFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern=pattern,
                    severity=severity,
                    message=message,
                    missing_flags=missing,
                    function=self._current_function(),
                )
            )
        self.generic_visit(node)


class InsecureCookieAnalyzer:
    """Detect cookies set without secure, httponly, or samesite flags.

    Flags Flask ``response.set_cookie``, Django ``set_cookie`` / ``set_signed_cookie``,
    and Starlette/FastAPI ``response.set_cookie`` calls missing recommended security
    attributes.
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
