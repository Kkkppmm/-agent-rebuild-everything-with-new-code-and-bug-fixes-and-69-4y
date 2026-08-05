"""SensitiveLoggingAnalyzer — detect passwords, tokens, and secrets written to logs."""

from __future__ import annotations

import ast
import re
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

_SENSITIVE_NAMES = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "auth_token",
        "bearer",
        "credential",
        "credentials",
        "private_key",
        "session_id",
        "session_key",
        "jwt",
        "authorization",
        "client_secret",
        "signing_key",
    }
)

_HIGH_SEVERITY = frozenset({"password", "passwd", "pwd", "secret", "private_key", "client_secret"})
_MEDIUM_SEVERITY = frozenset(
    {
        "token",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "auth_token",
        "jwt",
        "session_id",
        "session_key",
        "signing_key",
    }
)

_SENSITIVE_LITERAL = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|credential|authorization|bearer|jwt)\b"
)


@dataclass
class SensitiveLoggingFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    sink: str = ""
    identifier: str = ""

    def format(self) -> str:
        detail = ""
        if self.sink:
            detail += f" via {self.sink}"
        if self.identifier:
            detail += f" ({self.identifier})"
        return f"{self.path}:{self.lineno} [{self.severity}] {self.pattern}{detail}: {self.message}"


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


def _severity_for_name(name: str) -> str:
    lowered = name.lower()
    if lowered in _HIGH_SEVERITY:
        return "high"
    if lowered in _MEDIUM_SEVERITY:
        return "medium"
    return "low"


def _is_sensitive_name(name: str) -> bool:
    lowered = name.lower()
    if lowered in _SENSITIVE_NAMES:
        return True
    return any(keyword in lowered for keyword in _SENSITIVE_NAMES)


def _is_logging_sink(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name) and func.id == "print":
        return "print"
    if isinstance(func, ast.Attribute) and func.attr in _LOGGING_ATTRS:
        if isinstance(func.value, ast.Name) and func.value.id in {"logging", "logger", "log"}:
            return f"{func.value.id}.{func.attr}"
        if isinstance(func.value, ast.Attribute):
            if isinstance(func.value.value, ast.Name) and func.value.value.id == "logging":
                return f"logging.{func.attr}"
        return func.attr
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
        sink: str,
        identifier: str = "",
    ) -> None:
        lineno = getattr(node, "lineno", 1)
        self.findings.append(
            SensitiveLoggingFinding(
                path=self.path,
                lineno=lineno,
                pattern=pattern,
                severity=severity,
                message=message,
                sink=sink,
                identifier=identifier,
            )
        )

    def _check_expr(
        self,
        node: ast.expr,
        sink: str,
        call_node: ast.Call,
    ) -> None:
        name = _name_from_node(node)
        if name and _is_sensitive_name(name):
            self._add(
                call_node,
                pattern="sensitive_variable_logged",
                severity=_severity_for_name(name),
                message="Avoid logging sensitive values — logs are often persisted and broadly accessible",
                sink=sink,
                identifier=name,
            )
            return

        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    inner_name = _name_from_node(value.value)
                    if inner_name and _is_sensitive_name(inner_name):
                        self._add(
                            call_node,
                            pattern="sensitive_fstring_logged",
                            severity=_severity_for_name(inner_name),
                            message="f-string logs a sensitive variable — use structured logging with redaction",
                            sink=sink,
                            identifier=inner_name,
                        )
                        return
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    if _SENSITIVE_LITERAL.search(value.value):
                        self._add(
                            call_node,
                            pattern="sensitive_literal_in_log",
                            severity="medium",
                            message="Log message references sensitive data — redact or omit the value",
                            sink=sink,
                        )
                        return

        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if _SENSITIVE_LITERAL.search(node.value):
                self._add(
                    call_node,
                    pattern="sensitive_literal_in_log",
                    severity="medium",
                    message="Log message references sensitive data — redact or omit the value",
                    sink=sink,
                )

    def visit_Call(self, node: ast.Call) -> None:
        sink = _is_logging_sink(node)
        if sink:
            for arg in node.args:
                self._check_expr(arg, sink, node)
            for keyword in node.keywords:
                if keyword.arg in {"msg", "message", None} or keyword.arg is None:
                    self._check_expr(keyword.value, sink, node)
        self.generic_visit(node)


class SensitiveLoggingAnalyzer:
    """Detect passwords, tokens, and secrets written to stdout or log files."""

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
        high = sum(1 for f in self._findings if f.severity == "high")
        medium = sum(1 for f in self._findings if f.severity == "medium")
        low = sum(1 for f in self._findings if f.severity == "low")
        penalty = high * 25.0 + medium * 12.0 + low * 3.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Sensitive logging risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Sensitive logging analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No sensitive values logged to stdout or log files.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
