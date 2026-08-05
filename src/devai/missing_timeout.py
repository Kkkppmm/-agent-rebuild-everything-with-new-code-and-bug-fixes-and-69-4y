"""MissingTimeoutAnalyzer — detect HTTP, socket, and subprocess calls without timeouts."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_TIMEOUT_REQUIRED: dict[str, tuple[str, str]] = {
    "requests.get": ("missing_http_timeout", "requests.get() without timeout can hang indefinitely"),
    "requests.post": ("missing_http_timeout", "requests.post() without timeout can hang indefinitely"),
    "requests.put": ("missing_http_timeout", "requests.put() without timeout can hang indefinitely"),
    "requests.delete": ("missing_http_timeout", "requests.delete() without timeout can hang indefinitely"),
    "requests.head": ("missing_http_timeout", "requests.head() without timeout can hang indefinitely"),
    "requests.patch": ("missing_http_timeout", "requests.patch() without timeout can hang indefinitely"),
    "requests.request": ("missing_http_timeout", "requests.request() without timeout can hang indefinitely"),
    "httpx.get": ("missing_http_timeout", "httpx.get() without timeout can hang indefinitely"),
    "httpx.post": ("missing_http_timeout", "httpx.post() without timeout can hang indefinitely"),
    "httpx.put": ("missing_http_timeout", "httpx.put() without timeout can hang indefinitely"),
    "httpx.delete": ("missing_http_timeout", "httpx.delete() without timeout can hang indefinitely"),
    "httpx.head": ("missing_http_timeout", "httpx.head() without timeout can hang indefinitely"),
    "httpx.patch": ("missing_http_timeout", "httpx.patch() without timeout can hang indefinitely"),
    "httpx.request": ("missing_http_timeout", "httpx.request() without timeout can hang indefinitely"),
    "urlopen": ("missing_http_timeout", "urlopen() without timeout can hang indefinitely"),
    "create_connection": ("missing_socket_timeout", "socket.create_connection() without timeout can hang"),
    "connect": ("missing_socket_timeout", "socket.connect() without timeout can hang indefinitely"),
    "subprocess.run": ("missing_subprocess_timeout", "subprocess.run() without timeout can hang indefinitely"),
    "subprocess.call": ("missing_subprocess_timeout", "subprocess.call() without timeout can hang indefinitely"),
    "subprocess.check_call": (
        "missing_subprocess_timeout",
        "subprocess.check_call() without timeout can hang indefinitely",
    ),
    "subprocess.check_output": (
        "missing_subprocess_timeout",
        "subprocess.check_output() without timeout can hang indefinitely",
    ),
    "subprocess.Popen": ("missing_subprocess_timeout", "subprocess.Popen() without timeout can hang indefinitely"),
}

_HTTP_METHODS = frozenset({"get", "post", "put", "delete", "head", "patch", "request"})


@dataclass
class MissingTimeoutFinding:
    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    call: str = ""
    function: str = ""

    def format(self) -> str:
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        call = f" ({self.call})" if self.call else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}{call}: {self.message}"


@dataclass
class MissingTimeoutStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _call_label(node: ast.Call) -> str:
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
    return ""


def _has_timeout_kwarg(node: ast.Call) -> bool:
    return any(kw.arg == "timeout" for kw in node.keywords)


def _resolve_timeout_rule(label: str) -> tuple[str, str, str] | None:
    if label in _TIMEOUT_REQUIRED:
        pattern, message = _TIMEOUT_REQUIRED[label]
        severity = "medium" if label.startswith("subprocess") else "high"
        return pattern, severity, message

    if label.startswith("requests.") and label.split(".", 1)[1] in _HTTP_METHODS:
        pattern, message = _TIMEOUT_REQUIRED["requests.get"]
        return pattern, "high", message

    if label.startswith("httpx.") and label.split(".", 1)[1] in _HTTP_METHODS:
        pattern, message = _TIMEOUT_REQUIRED["httpx.get"]
        return pattern, "high", message

    if label.endswith(".urlopen"):
        pattern, message = _TIMEOUT_REQUIRED["urlopen"]
        return pattern, "high", message

    if label.endswith(".create_connection"):
        pattern, message = _TIMEOUT_REQUIRED["create_connection"]
        return pattern, "high", message

    if label.endswith(".connect") and "socket" in label:
        pattern, message = _TIMEOUT_REQUIRED["connect"]
        return pattern, "high", message

    if label.startswith("subprocess."):
        attr = label.split(".", 1)[1]
        if attr in _TIMEOUT_REQUIRED:
            pattern, message = _TIMEOUT_REQUIRED[f"subprocess.{attr}"]
            return pattern, "medium", message

    return None


class _MissingTimeoutVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[MissingTimeoutFinding] = []
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
        label = _call_label(node)
        if label and not _has_timeout_kwarg(node):
            rule = _resolve_timeout_rule(label)
            if rule:
                pattern, severity, message = rule
                self.findings.append(
                    MissingTimeoutFinding(
                        path=self.path,
                        lineno=node.lineno,
                        pattern=pattern,
                        severity=severity,
                        message=message,
                        call=label,
                        function=self._current_function(),
                    )
                )
        self.generic_visit(node)


class MissingTimeoutAnalyzer:
    """Detect HTTP, socket, and subprocess calls missing timeout parameters."""

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
        penalty = high * 20.0 + medium * 10.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Missing timeouts: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Missing timeout analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No calls missing timeouts found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
