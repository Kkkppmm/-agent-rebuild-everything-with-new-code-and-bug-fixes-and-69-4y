"""LogInjectionAnalyzer — detect log injection risks from dynamic log messages."""

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


@dataclass
class LogInjectionFinding:
    """A potentially unsafe dynamic log message."""

    path: str
    lineno: int
    name: str
    severity: str
    message: str
    context: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        ctx = f" ({self.context})" if self.context else ""
        return (
            f"{self.path}:{self.lineno} [{self.severity}] {self.name}{ctx}: "
            f"{self.message}"
        )


@dataclass
class LogInjectionStats:
    """Aggregate log-injection analysis statistics."""

    total_findings: int
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


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


def _has_dynamic_message(args: list[ast.expr]) -> bool:
    if not args:
        return False
    msg = args[0]
    if isinstance(msg, ast.JoinedStr):
        return True
    if isinstance(msg, ast.BinOp) and isinstance(msg.op, ast.Mod):
        return True
    if isinstance(msg, ast.Call) and isinstance(msg.func, ast.Attribute):
        if msg.func.attr == "format":
            return True
    if isinstance(msg, ast.BinOp) and isinstance(msg.op, ast.Add):
        return True
    return False


class _LogInjectionVisitor(ast.NodeVisitor):
    """Walk a module AST and collect log injection risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[LogInjectionFinding] = []

    def _add(
        self,
        node: ast.AST,
        name: str,
        *,
        severity: str,
        message: str,
        context: str = "",
    ) -> None:
        self.findings.append(
            LogInjectionFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                name=name,
                severity=severity,
                message=message,
                context=context,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _is_logging_call(node)
        if call_name and _has_dynamic_message(list(node.args)):
            severity = "medium" if call_name == "print" else "high"
            self._add(
                node,
                call_name,
                severity=severity,
                message="Dynamic log message — use structured logging with extra={} to prevent injection",
                context="dynamic message",
            )
        elif call_name and len(node.args) > 1:
            msg = node.args[0]
            if isinstance(msg, ast.Constant) and isinstance(msg.value, str):
                if "%" in msg.value or "{" in msg.value:
                    self._add(
                        node,
                        call_name,
                        severity="high",
                        message="Log message with placeholders — pass user data via extra={}, not interpolation",
                        context="positional args",
                    )
        self.generic_visit(node)


class LogInjectionAnalyzer:
    """Detect log injection risks from dynamic log message construction.

    Flags f-strings, ``%`` formatting, and ``.format()`` in ``logging`` calls
    where user-controlled data can forge or corrupt log entries.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[LogInjectionFinding] = []
        self._stats: LogInjectionStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[LogInjectionFinding]:
        """Analyze the project and return log-injection findings."""
        if self._findings:
            return self._findings

        findings: list[LogInjectionFinding] = []
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
            visitor = _LogInjectionVisitor(rel)
            visitor.visit(tree)
            if visitor.findings:
                files_with_findings.add(rel)
            findings.extend(visitor.findings)

        self._findings = findings
        self._files_scanned = files_scanned

        by_severity: dict[str, int] = {}
        for finding in findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

        self._stats = LogInjectionStats(
            total_findings=len(findings),
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> LogInjectionStats:
        """Return aggregate log-injection statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[LogInjectionFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no log injection risks)."""
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
        high = stats.by_severity.get("high", 0)
        lines = [
            f"Log injection: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing log-injection findings."""
        self.analyze()
        lines = [
            "Log injection analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No log injection risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
