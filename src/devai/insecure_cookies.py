"""InsecureCookieAnalyzer — detect cookies missing secure, httponly, or samesite flags."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_SET_COOKIE_RE = re.compile(r"set_cookie|setCookie|SET_COOKIE", re.IGNORECASE)


@dataclass
class InsecureCookieFinding:
    """A detected insecure cookie configuration."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""
    call: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        call = f" ({self.call})" if self.call else ""
        return f"{loc}{fn}{call} [{self.severity}] {self.pattern}: {self.message}"


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


def _has_kw(node: ast.Call, name: str, value: bool = True) -> bool:
    for kw in node.keywords:
        if kw.arg == name:
            if isinstance(kw.value, ast.Constant):
                return kw.value.value == value
    return False


def _is_set_cookie_call(node: ast.Call) -> bool:
    name = _call_name(node)
    return name.endswith("set_cookie") or name.endswith("setCookie")


class _InsecureCookieVisitor(ast.NodeVisitor):
    """Walk a module AST and collect insecure cookie patterns."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[InsecureCookieFinding] = []
        self._function_stack: list[str] = []

    def _current_function(self) -> str:
        return self._function_stack[-1] if self._function_stack else ""

    def _add(
        self,
        node: ast.AST,
        pattern: str,
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
                function=self._current_function(),
                call=call,
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
        if not _is_set_cookie_call(node):
            self.generic_visit(node)
            return

        name = _call_name(node)
        has_secure = _has_kw(node, "secure", True)
        has_httponly = _has_kw(node, "httponly", True) or _has_kw(node, "http_only", True)
        has_samesite = any(kw.arg == "samesite" for kw in node.keywords)

        if not has_secure:
            self._add(
                node,
                "missing_secure_flag",
                "high",
                "Cookie set without secure=True — may be sent over HTTP",
                call=name,
            )
        if not has_httponly:
            self._add(
                node,
                "missing_httponly_flag",
                "medium",
                "Cookie set without httponly=True — accessible via JavaScript",
                call=name,
            )
        if not has_samesite:
            self._add(
                node,
                "missing_samesite",
                "medium",
                "Cookie set without samesite attribute — vulnerable to CSRF",
                call=name,
            )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in {
                "SESSION_COOKIE_SECURE",
                "CSRF_COOKIE_SECURE",
            }:
                if isinstance(node.value, ast.Constant) and node.value.value is False:
                    self._add(
                        node,
                        "session_cookie_insecure",
                        "high",
                        f"{target.id}=False allows cookies over unencrypted connections",
                    )
            if isinstance(target, ast.Name) and target.id in {
                "SESSION_COOKIE_HTTPONLY",
                "CSRF_COOKIE_HTTPONLY",
            }:
                if isinstance(node.value, ast.Constant) and node.value.value is False:
                    self._add(
                        node,
                        "session_cookie_no_httponly",
                        "medium",
                        f"{target.id}=False allows JavaScript access to cookies",
                    )
            if isinstance(target, ast.Attribute) and target.attr in {
                "SESSION_COOKIE_SECURE",
                "CSRF_COOKIE_SECURE",
            }:
                if isinstance(node.value, ast.Constant) and node.value.value is False:
                    self._add(
                        node,
                        "session_cookie_insecure",
                        "high",
                        f"{target.attr}=False allows cookies over unencrypted connections",
                    )
            if isinstance(target, ast.Attribute) and target.attr in {
                "SESSION_COOKIE_HTTPONLY",
                "CSRF_COOKIE_HTTPONLY",
            }:
                if isinstance(node.value, ast.Constant) and node.value.value is False:
                    self._add(
                        node,
                        "session_cookie_no_httponly",
                        "medium",
                        f"{target.attr}=False allows JavaScript access to cookies",
                    )
        self.generic_visit(node)


class InsecureCookieAnalyzer:
    """Detect cookies missing security flags in web applications.

    Flags set_cookie() calls without secure, httponly, or samesite attributes,
    and Django SESSION_COOKIE_SECURE/HTTPONLY settings set to False.
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
        penalty = high * 20.0 + medium * 10.0
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
            lines.append("No insecure cookie configurations found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
