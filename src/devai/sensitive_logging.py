"""SensitiveLoggingAnalyzer — detect passwords, tokens, and secrets logged to output."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_LOGGING_ATTRS = frozenset(
    {
        "debug",
        "info",
        "warning",
        "warn",
        "error",
        "critical",
        "exception",
        "log",
    }
)

_SENSITIVE_KEYWORDS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_key",
        "private_key",
        "credential",
        "credentials",
        "auth",
        "authorization",
        "bearer",
        "session",
        "cookie",
        "ssn",
        "credit_card",
        "creditcard",
        "cvv",
        "pin",
        "otp",
        "refresh_token",
        "access_token",
        "client_secret",
        "jwt",
        "oauth",
    }
)


@dataclass
class SensitiveLoggingFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    sink: str = ""
    context: str = ""

    def format(self) -> str:
        sink = f" via {self.sink}" if self.sink else ""
        ctx = f" ({self.context})" if self.context else ""
        return (
            f"{self.path}:{self.lineno}{sink}{ctx} [{self.severity}] "
            f"{self.pattern}: {self.message}"
        )


@dataclass
class SensitiveLoggingStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_test_path(rel: str) -> bool:
    parts = Path(rel).parts
    if "tests" in parts or "test" in parts:
        return True
    name = Path(rel).name
    return name.startswith("test_") or name.endswith("_test.py")


def _name_from_node(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _contains_sensitive_name(node: ast.expr) -> str | None:
    for child in ast.walk(node):
        name = _name_from_node(child)
        if name:
            lowered = name.lower()
            if lowered in _SENSITIVE_KEYWORDS:
                return name
            if any(keyword in lowered for keyword in _SENSITIVE_KEYWORDS):
                return name
    return None


def _is_logging_call(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in _LOGGING_ATTRS:
        if isinstance(func.value, ast.Name) and func.value.id in {"logging", "logger", "log"}:
            return f"{func.value.id}.{func.attr}"
        if isinstance(func.value, ast.Attribute):
            if isinstance(func.value.value, ast.Name) and func.value.value.id == "logging":
                return f"logging.{func.attr}"
        return func.attr
    if isinstance(func, ast.Name) and func.id == "print":
        return "print"
    return None


class _SensitiveLoggingVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[SensitiveLoggingFinding] = []

    def _add(
        self,
        node: ast.AST,
        *,
        pattern: str,
        severity: str,
        message: str,
        sink: str = "",
        context: str = "",
    ) -> None:
        self.findings.append(
            SensitiveLoggingFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
                sink=sink,
                context=context,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        sink = _is_logging_call(node)
        if not sink:
            self.generic_visit(node)
            return

        for arg in node.args:
            sensitive = _contains_sensitive_name(arg)
            if sensitive:
                severity = "critical" if sink == "print" else "high"
                self._add(
                    node,
                    pattern="sensitive_value_logged",
                    severity=severity,
                    message=(
                        f"Sensitive value '{sensitive}' may be written to logs — "
                        "redact or mask before logging"
                    ),
                    sink=sink,
                    context=sensitive,
                )

        for keyword in node.keywords:
            if keyword.arg in {"extra", "exc_info", "stack_info", "stacklevel"}:
                continue
            sensitive = _contains_sensitive_name(keyword.value)
            if sensitive:
                self._add(
                    node,
                    pattern="sensitive_kwarg_logged",
                    severity="high",
                    message=(
                        f"Sensitive keyword '{keyword.arg}' logs value '{sensitive}' — "
                        "avoid logging secrets"
                    ),
                    sink=sink,
                    context=keyword.arg or "",
                )

        self.generic_visit(node)


class SensitiveLoggingAnalyzer:
    """Detect passwords, tokens, and secrets logged to stdout or log files."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[SensitiveLoggingFinding] = []
        self._stats: SensitiveLoggingStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        if path.suffix != ".py":
            return True
        rel = str(path.relative_to(self.root))
        return _is_test_path(rel)

    def analyze(self) -> list[SensitiveLoggingFinding]:
        if self._findings:
            return self._findings

        findings: list[SensitiveLoggingFinding] = []
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
            visitor = _SensitiveLoggingVisitor(rel)
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
        self._stats = SensitiveLoggingStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> SensitiveLoggingStats:
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        critical = sum(1 for f in self._findings if f.severity == "critical")
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        penalty = critical * 30.0 + high * 20.0 + medium * 8.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Sensitive logging: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Sensitive logging analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No sensitive values logged to output.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
