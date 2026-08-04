"""HeaderInjectionAnalyzer — detect HTTP header injection (CRLF) risks."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_REQUEST_SOURCES = frozenset(
    {
        "request",
        "request.args",
        "request.form",
        "request.values",
        "request.GET",
        "request.POST",
        "request.query_params",
        "request.path_params",
        "request.headers",
        "request.data",
        "request.json",
    }
)
_HEADER_ATTRS = frozenset({"headers", "set_header", "add_header", "setdefault"})


@dataclass
class HeaderInjectionFinding:
    """A potentially unsafe HTTP header assignment."""

    path: str
    lineno: int
    pattern: str
    severity: str
    message: str
    function: str = ""

    def format(self) -> str:
        """Return a single-line description."""
        loc = f"{self.path}:{self.lineno}"
        fn = f" in {self.function}" if self.function else ""
        return f"{loc}{fn} [{self.severity}] {self.pattern}: {self.message}"


@dataclass
class HeaderInjectionStats:
    """Aggregate header-injection analysis statistics."""

    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _request_source(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name) and node.id == "request":
        return "request"
    if isinstance(node, ast.Attribute):
        base = _request_source(node.value)
        if base:
            return f"{base}.{node.attr}"
    return None


def _is_request_access(node: ast.AST) -> bool:
    if _request_source(node) in _REQUEST_SOURCES:
        return True
    if isinstance(node, ast.Attribute):
        base = _request_source(node.value)
        if base and node.attr in {"args", "form", "values", "GET", "POST", "headers", "data", "json"}:
            return True
    if isinstance(node, ast.Subscript):
        return _is_request_access(node.value)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"get", "pop", "getlist"}:
            return _is_request_access(func.value)
    if isinstance(node, ast.JoinedStr):
        return any(
            isinstance(v, ast.FormattedValue) and _is_user_controlled(v.value)
            for v in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_user_controlled(node.left) or _is_user_controlled(node.right)
    if isinstance(node, ast.Name):
        return node.id in {"user_input", "value", "header_value", "location", "url"}
    return False


def _is_user_controlled(node: ast.AST) -> bool:
    return _is_request_access(node)


class _HeaderInjectionVisitor(ast.NodeVisitor):
    """Walk a module AST and collect header injection risks."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[HeaderInjectionFinding] = []
        self._function_stack: list[str] = []

    def _add(
        self,
        node: ast.AST,
        pattern: str,
        *,
        severity: str,
        message: str,
    ) -> None:
        fn = self._function_stack[-1] if self._function_stack else ""
        self.findings.append(
            HeaderInjectionFinding(
                path=self.path,
                lineno=getattr(node, "lineno", 0),
                pattern=pattern,
                severity=severity,
                message=message,
                function=fn,
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

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Subscript):
                sub = target
                if isinstance(sub.value, ast.Attribute) and sub.value.attr == "headers":
                    if _is_user_controlled(node.value):
                        self._add(
                            node,
                            "headers[key]=user_input",
                            severity="high",
                            message="User-controlled header value — validate and strip CRLF characters",
                        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr in {"set_header", "add_header"} and node.args:
                if _is_user_controlled(node.args[0]) or (
                    len(node.args) > 1 and _is_user_controlled(node.args[1])
                ):
                    self._add(
                        node,
                        func.attr,
                        severity="high",
                        message="User-controlled header — validate and strip CRLF characters",
                    )
            if func.attr == "setdefault" and isinstance(func.value, ast.Attribute):
                if func.value.attr == "headers" and node.args and _is_user_controlled(node.args[0]):
                    self._add(
                        node,
                        "headers.setdefault",
                        severity="medium",
                        message="User-controlled header key — validate header names and values",
                    )
        self.generic_visit(node)


class HeaderInjectionAnalyzer:
    """Detect HTTP header injection risks from user-controlled header values.

    Flags assignments to response headers, ``set_header`` / ``add_header`` calls,
    and dynamic header keys where untrusted input can inject CRLF sequences.
    """

    def __init__(
        self,
        root: str,
        *,
        ignore_dirs: set[str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[HeaderInjectionFinding] = []
        self._stats: HeaderInjectionStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def analyze(self) -> list[HeaderInjectionFinding]:
        """Analyze the project and return header-injection findings."""
        if self._findings:
            return self._findings

        findings: list[HeaderInjectionFinding] = []
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
            visitor = _HeaderInjectionVisitor(rel)
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

        self._stats = HeaderInjectionStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> HeaderInjectionStats:
        """Return aggregate header-injection statistics."""
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def high_severity(self) -> list[HeaderInjectionFinding]:
        """Return only high-severity findings."""
        return [f for f in self.analyze() if f.severity == "high"]

    def health_score(self) -> float:
        """Return a 0-100 health score (100 = no header injection risks)."""
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
            f"Header injection: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)",
            f"Density: {stats.finding_density} findings per 100 files",
            f"High severity: {high}",
            f"Health score: {self.health_score()}/100",
        ]
        return "\n".join(lines)

    def to_context(self, limit: int = 30) -> str:
        """Build LLM-ready context describing header-injection findings."""
        self.analyze()
        lines = [
            "Header injection analysis:",
            self.summary(),
            "",
            "Findings:",
        ]
        if not self._findings:
            lines.append("No header injection risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
            if len(self._findings) > limit:
                lines.append(f"... and {len(self._findings) - limit} more")
        return "\n".join(lines)
