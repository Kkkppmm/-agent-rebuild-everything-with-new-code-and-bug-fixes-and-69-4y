"""LogInjectionAnalyzer — detect dynamic log message construction risks."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_USER_INPUT_RE = re.compile(
    r"(request|user|input|param|query|header|cookie|body|payload|message|"
    r"username|email|ip|addr|remote|client|session|token|name|value|data)",
    re.IGNORECASE,
)

_LOG_ATTRS = frozenset(
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
    """A potentially unsafe dynamic log message construction."""

    path: str
    lineno: int
    method: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        fn = f" in {self.function}" if self.function else ""
        return (
            f"{self.path}:{self.lineno}{fn} [{self.severity}] {self.method}: "
            f"{self.message}"
        )


@dataclass
class LogInjectionStats:
    """Aggregate log-injection analysis statistics."""

    total_findings: int
    by_method: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _looks_like_user_input(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return bool(_USER_INPUT_RE.search(node.id))
    if isinstance(node, ast.Attribute):
        return bool(_USER_INPUT_RE.search(node.attr))
    if isinstance(node, ast.Subscript):
        return _looks_like_user_input(node.value)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            return _looks_like_user_input(node.func)
    return False


def _is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(
            _looks_like_user_input(v.value)
            for v in node.values
            if isinstance(v, ast.FormattedValue)
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left_str = isinstance(node.left, (ast.Constant, ast.JoinedStr)) and (
            not isinstance(node.left, ast.Constant) or isinstance(node.left.value, str)
        )
        right_str = isinstance(node.right, (ast.Constant, ast.JoinedStr)) and (
            not isinstance(node.right, ast.Constant) or isinstance(node.right.value, str)
        )
        if left_str or right_str:
            return _looks_like_user_input(node.left) or _looks_like_user_input(node.right)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"format", "replace"}:
            return _looks_like_user_input(node.func.value)
    return _looks_like_user_input(node)


def _log_call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in _LOG_ATTRS:
        if isinstance(func.value, ast.Name):
            if func.value.id in {"logging", "logger", "log"}:
                return f"{func.value.id}.{func.attr}"
            return func.attr
        return func.attr
    if isinstance(func, ast.Name) and func.id == "print":
        return "print"
    return None


class _LogInjectionVisitor(ast.NodeVisitor):
    """Walk a module AST and collect dynamic log message risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[LogInjectionFinding] = []
        self._function_stack: list[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        method = _log_call_name(node)
        if method and node.args:
            msg_arg = node.args[0]
            if _is_dynamic_string(msg_arg):
                self.findings.append(
                    LogInjectionFinding(
                        path=self.path,
                        lineno=node.lineno,
                        method=method,
                        severity="medium",
                        message="User-controlled data in log message — use structured logging with %s placeholders",
                        function=self._function_stack[-1] if self._function_stack else "",
                    )
                )
            elif isinstance(msg_arg, ast.Call):
                call_func = msg_arg.func
                if isinstance(call_func, ast.Attribute) and call_func.attr == "format":
                    if _looks_like_user_input(call_func.value):
                        self.findings.append(
                            LogInjectionFinding(
                                path=self.path,
                                lineno=node.lineno,
                                method=method,
                                severity="medium",
                                message="Dynamic .format() in log message — risk of log injection/forging",
                                function=self._function_stack[-1] if self._function_stack else "",
                            )
                        )
        self.generic_visit(node)


class LogInjectionAnalyzer:
    """Detect dynamic log message construction from user-controlled input.

    Flags f-strings, concatenation, and ``.format()`` calls in ``logging``,
    ``logger``, and ``print`` statements that may allow log injection or forging.
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

        by_method: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_method[finding.method] = by_method.get(finding.method, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = 0.0
        if files_scanned:
            density = round(100.0 * len(findings) / files_scanned, 1)

        self._stats = LogInjectionStats(
            total_findings=len(findings),
            by_method=by_method,
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
        penalty = high * 25.0 + medium * 10.0
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
