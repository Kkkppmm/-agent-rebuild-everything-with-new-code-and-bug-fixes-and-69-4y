"""InsecureCookieAnalyzer — detect insecure session and cookie configurations."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_INSECURE_SESSION_ATTRS = {
    "SESSION_COOKIE_SECURE": (False, "medium", "Session cookies should use secure=True in production"),
    "SESSION_COOKIE_HTTPONLY": (False, "high", "Session cookies should use httponly=True to prevent XSS theft"),
    "SESSION_COOKIE_SAMESITE": (None, "medium", "Session cookies should set samesite='Lax' or 'Strict'"),
}
_COOKIE_CALLS = frozenset({"set_cookie", "set_signed_cookie", "set_unsign_cookie"})


@dataclass
class InsecureCookieFinding:
    """An insecure cookie or session configuration."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    call: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        call = f" ({self.call})" if self.call else ""
        return (
            f"{self.path}:{self.lineno}{call} [{self.severity}] {self.pattern}: "
            f"{self.message}"
        )


@dataclass
class InsecureCookieStats:
    """Aggregate insecure cookie analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _kw_bool(node: ast.keyword) -> bool | None:
    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, bool):
        return node.value.value
    return None


def _kw_string(node: ast.keyword) -> str | None:
    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
        return node.value.value
    return None


class _InsecureCookieVisitor(ast.NodeVisitor):
    """Walk a module AST and collect insecure cookie configurations."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InsecureCookieFinding] = []

    def _add(
        self,
        node: ast.AST,
        pattern: str,
        *,
        severity: str,
        message: str,
        call: str = "",
    ) -> None:
        self.findings.append(
            InsecureCookieFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
                call=call,
            )
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in _INSECURE_SESSION_ATTRS:
                expected, severity, message = _INSECURE_SESSION_ATTRS[target.id]
                if isinstance(node.value, ast.Constant) and node.value.value == expected:
                    self._add(
                        node,
                        f"session_{target.id.lower()}",
                        severity=severity,
                        message=message,
                        call=target.id,
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        if name in _COOKIE_CALLS:
            secure = None
            httponly = None
            samesite = None
            for kw in node.keywords:
                if kw.arg == "secure":
                    secure = _kw_bool(kw)
                elif kw.arg == "httponly":
                    httponly = _kw_bool(kw)
                elif kw.arg == "samesite":
                    samesite = _kw_string(kw)

            if secure is False:
                self._add(
                    node,
                    "cookie_missing_secure",
                    severity="medium",
                    message="Cookie set without secure=True — vulnerable to interception over HTTP",
                    call=name,
                )
            if httponly is False:
                self._add(
                    node,
                    "cookie_missing_httponly",
                    severity="high",
                    message="Cookie set without httponly=True — accessible to JavaScript (XSS risk)",
                    call=name,
                )
            if samesite is not None and samesite.lower() == "none":
                self._add(
                    node,
                    "cookie_samesite_none",
                    severity="medium",
                    message="samesite='none' requires secure=True and increases CSRF risk",
                    call=name,
                )
            if secure is None and httponly is None:
                self._add(
                    node,
                    "cookie_no_security_flags",
                    severity="low",
                    message="set_cookie() without explicit secure/httponly flags — verify defaults",
                    call=name,
                )

        self.generic_visit(node)


class InsecureCookieAnalyzer:
    """Detect insecure session and cookie settings in Flask, Django, and Starlette apps.

    Flags missing secure/httponly flags on set_cookie calls and insecure
    SESSION_COOKIE_* configuration constants.
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
        """Return high and critical severity findings."""
        return [f for f in self.analyze() if f.severity in {"critical", "high"}]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no insecure cookie settings)."""
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        critical = sum(1 for f in self._findings if f.severity == "critical")
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = critical * 40.0 + high * 25.0 + medium * 10.0 + low * 5.0
        ratio = penalty / self._files_scanned
        return round(max(0.0, 100.0 - ratio), 1)

    def summary(self) -> str:
        """Return a human-readable summary."""
        self.analyze()
        stats = self.stats
        high = stats.by_severity.get("high", 0)
        medium = stats.by_severity.get("medium", 0)
        lines = [
            f"Insecure cookies: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High: {high}, Medium: {medium}",
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
