"""MissingTimeoutAnalyzer — detect HTTP, socket, and subprocess calls without timeouts."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_HTTP_MODULES = frozenset({"requests", "httpx", "urllib", "aiohttp", "urllib3"})
_HTTP_METHODS = frozenset(
    {"get", "post", "put", "delete", "patch", "head", "options", "request", "urlopen", "fetch"}
)
_SOCKET_CALLS = frozenset({"create_connection", "connect", "connect_ex"})
_SUBPROCESS_CALLS = frozenset({"run", "call", "check_call", "check_output", "Popen"})


@dataclass
class MissingTimeoutFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    call: str = ""

    def format(self) -> str:
        call = f" ({self.call})" if self.call else ""
        return f"{self.path}:{self.lineno}{call} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class MissingTimeoutStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_label(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Attribute):
        attr = func.attr
        if isinstance(func.value, ast.Name):
            return f"{func.value.id}.{attr}"
        if isinstance(func.value, ast.Attribute) and isinstance(func.value.value, ast.Name):
            return f"{func.value.value.id}.{func.value.attr}.{attr}"
        return attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _has_timeout_kwarg(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg == "timeout":
            return True
    return False


def _is_http_call_without_timeout(node: ast.Call) -> tuple[str, str, str] | None:
    label = _call_label(node)
    if not label:
        return None
    if _has_timeout_kwarg(node):
        return None

    parts = label.split(".")
    if len(parts) >= 2:
        module = parts[0]
        method = parts[-1]
        if module in _HTTP_MODULES and method in _HTTP_METHODS:
            return (
                "http_no_timeout",
                "medium",
                f"HTTP call {label}() without timeout= may hang indefinitely",
                label,
            )
    if label == "urlopen":
        return (
            "http_no_timeout",
            "medium",
            "urlopen() without timeout= may hang indefinitely",
            label,
        )
    return None


def _is_socket_call_without_timeout(node: ast.Call) -> tuple[str, str, str] | None:
    label = _call_label(node)
    if not label:
        return None
    if _has_timeout_kwarg(node):
        return None

    parts = label.split(".")
    method = parts[-1]
    if method in _SOCKET_CALLS:
        return (
            "socket_no_timeout",
            "medium",
            f"Socket call {label}() without timeout may hang indefinitely",
            label,
        )
    return None


def _is_subprocess_call_without_timeout(node: ast.Call) -> tuple[str, str, str] | None:
    label = _call_label(node)
    if not label:
        return None
    if _has_timeout_kwarg(node):
        return None

    parts = label.split(".")
    if len(parts) >= 2 and parts[0] == "subprocess" and parts[1] in _SUBPROCESS_CALLS:
        return (
            "subprocess_no_timeout",
            "medium",
            f"Subprocess {label}() without timeout= may hang indefinitely",
            label,
        )
    return None


class _MissingTimeoutVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[MissingTimeoutFinding] = []

    def visit_Call(self, node: ast.Call) -> None:
        for checker in (
            _is_http_call_without_timeout,
            _is_socket_call_without_timeout,
            _is_subprocess_call_without_timeout,
        ):
            result = checker(node)
            if result:
                pattern, severity, message, call = result
                self.findings.append(
                    MissingTimeoutFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern=pattern,
                        severity=severity,
                        message=message,
                        call=call,
                    )
                )
                break
        self.generic_visit(node)


class MissingTimeoutAnalyzer:
    """Detect network and subprocess calls that omit timeout parameters."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[MissingTimeoutFinding] = []
        self._stats: MissingTimeoutStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[MissingTimeoutFinding]:
        if self._findings:
            return self._findings

        findings: list[MissingTimeoutFinding] = []
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
            visitor = _MissingTimeoutVisitor(rel)
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
        self._stats = MissingTimeoutStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> MissingTimeoutStats:
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
        penalty = high * 25.0 + medium * 12.0 + low * 5.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Missing timeout risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Missing timeout analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No calls missing timeout parameters found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
