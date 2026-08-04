"""HeaderInjectionAnalyzer — detect user-controlled data in HTTP response headers."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_HEADER_METHODS = frozenset({"set_header", "add_header", "setdefault", "__setitem__"})
_HEADER_ATTRS = frozenset({"headers", "response"})
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
    }
)


@dataclass
class HeaderInjectionFinding:
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
class HeaderInjectionStats:
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


def _is_user_controlled(node: ast.AST) -> bool:
    src = _request_source(node)
    if src and any(src.startswith(r) or src == r for r in _REQUEST_SOURCES):
        return True
    if isinstance(node, ast.Subscript) and _is_user_controlled(node.value):
        return True
    if isinstance(node, ast.Attribute) and _is_user_controlled(node.value):
        return True
    return False


class _HeaderInjectionVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[HeaderInjectionFinding] = []
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
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr in _HEADER_METHODS:
                value_arg = node.args[1] if len(node.args) > 1 else None
                if value_arg and _is_user_controlled(value_arg):
                    self.findings.append(
                        HeaderInjectionFinding(
                            path=self.path,
                            lineno=node.lineno,
                            pattern="user_input_in_header",
                            severity="high",
                            message="User-controlled data used in HTTP response header",
                            function=self._current_function(),
                        )
                    )
            if func.attr == "set" and isinstance(func.value, ast.Attribute):
                if func.value.attr in _HEADER_ATTRS and len(node.args) >= 2:
                    if _is_user_controlled(node.args[1]):
                        self.findings.append(
                            HeaderInjectionFinding(
                                path=self.path,
                                lineno=node.lineno,
                                pattern="user_input_in_header",
                                severity="high",
                                message="User-controlled data used in HTTP response header",
                                function=self._current_function(),
                            )
                        )
        self.generic_visit(node)


class HeaderInjectionAnalyzer:
    """Detect user-controlled values placed into HTTP response headers."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
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

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
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
        if self._stats is None:
            self.analyze()
        return self._stats  # type: ignore[return-value]

    def health_score(self) -> float:
        self.analyze()
        if self._files_scanned == 0:
            return 100.0
        high = sum(1 for f in self._findings if f.severity == "high")
        penalty = high * 25.0
        return round(max(0.0, 100.0 - penalty / self._files_scanned), 1)

    def summary(self) -> str:
        self.analyze()
        stats = self.stats
        return (
            f"Header injection risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["Header injection analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No header injection risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
