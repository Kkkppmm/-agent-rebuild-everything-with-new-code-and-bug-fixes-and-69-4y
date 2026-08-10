"""SensitiveLoggingAnalyzer — detect sensitive data logged to stdout or log files."""

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
        "private_key",
        "auth_token",
        "credential",
        "credentials",
        "session_key",
        "jwt",
        "bearer",
        "authorization",
        "client_secret",
        "signing_key",
    }
)

_SENSITIVE_TEMPLATE_FRAGMENTS = frozenset(
    {
        "password=",
        "passwd=",
        "token=",
        "secret=",
        "api_key=",
        "apikey=",
        "authorization:",
        "bearer ",
    }
)


@dataclass
class SensitiveLoggingFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class SensitiveLoggingStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_sensitive_name(name: str) -> bool:
    lowered = name.lower()
    if lowered in _SENSITIVE_NAMES:
        return True
    return any(keyword in lowered for keyword in _SENSITIVE_NAMES)


def _name_from_node(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
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


def _expr_has_sensitive_name(node: ast.expr) -> bool:
    for child in ast.walk(node):
        name = _name_from_node(child)
        if name and _is_sensitive_name(name):
            return True
    return False


def _joined_str_has_sensitive_template(node: ast.JoinedStr) -> bool:
    for part in node.values:
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            lowered = part.value.lower()
            if any(fragment in lowered for fragment in _SENSITIVE_TEMPLATE_FRAGMENTS):
                return True
    return _expr_has_sensitive_name(node)


class _SensitiveLoggingVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[SensitiveLoggingFinding] = []
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
            SensitiveLoggingFinding(
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

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _is_logging_call(node)
        if not call_name:
            self.generic_visit(node)
            return

        args = list(node.args)
        if not args:
            self.generic_visit(node)
            return

        first = args[0]
        if isinstance(first, ast.Name) and _is_sensitive_name(first.id):
            self._add(
                node,
                pattern="sensitive_arg",
                severity="high",
                message=f"Sensitive value '{first.id}' passed directly to {call_name}",
            )
        elif isinstance(first, ast.JoinedStr) and _joined_str_has_sensitive_template(first):
            self._add(
                node,
                pattern="sensitive_fstring",
                severity="high",
                message=f"Sensitive data interpolated into {call_name} f-string",
            )
        elif _expr_has_sensitive_name(first):
            self._add(
                node,
                pattern="sensitive_message",
                severity="high",
                message=f"Sensitive data embedded in {call_name} message",
            )

        for arg in args[1:]:
            if _expr_has_sensitive_name(arg):
                self._add(
                    node,
                    pattern="sensitive_format_arg",
                    severity="high",
                    message=f"Sensitive data passed as format argument to {call_name}",
                )

        self.generic_visit(node)


class SensitiveLoggingAnalyzer:
    """Detect passwords, tokens, and secrets written to logs or stdout."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[SensitiveLoggingFinding] = []
        self._stats: SensitiveLoggingStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

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
        penalty = high * 25.0 + medium * 10.0
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
            lines.append("No sensitive data logging risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
