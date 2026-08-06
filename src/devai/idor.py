"""IDORAnalyzer — detect insecure direct object reference patterns."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from devai.project import DEFAULT_IGNORE_DIRS

_LOOKUP_METHODS = frozenset({"get", "filter", "filter_by", "find", "find_one", "find_by_id", "get_or_404"})
_ID_ATTRS = frozenset({"id", "pk", "user_id", "account_id", "object_id", "doc_id", "file_id", "record_id"})
_REQUEST_ATTRS = frozenset(
    {
        "args",
        "form",
        "json",
        "data",
        "values",
        "GET",
        "POST",
        "query_params",
        "path_params",
        "params",
    }
)
_LINE_PATTERNS = (
    re.compile(r"\.get\s*\([^)]*request\.(args|form|json|GET|POST)"),
    re.compile(r"\.filter(?:_by)?\s*\([^)]*(?:id|pk)\s*=\s*request\."),
    re.compile(r"find(?:_one|_by_id)?\s*\([^)]*request\.(args|json)"),
)


@dataclass
class IDORFinding:
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
class IDORStats:
    total_findings: int
    by_pattern: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    files_with_findings: int = 0
    finding_density: float = 0.0


def _is_request_data(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute) and node.attr in _REQUEST_ATTRS:
        if isinstance(node.value, ast.Name) and node.value.id == "request":
            return True
    if isinstance(node, ast.Subscript):
        value = node.value
        if isinstance(value, ast.Attribute) and value.attr in _REQUEST_ATTRS:
            if isinstance(value.value, ast.Name) and value.value.id == "request":
                return True
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"get", "get_json", "dict"}:
            if isinstance(func.value, ast.Name) and func.value.id == "request":
                return True
    return False


def _is_id_lookup(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in _LOOKUP_METHODS:
        for kw in node.keywords:
            if kw.arg in _ID_ATTRS and _is_request_data(kw.value):
                return True
        for arg in node.args:
            if _is_request_data(arg):
                return True
    return False


class _IDORVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.findings: list[IDORFinding] = []
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
        if _is_id_lookup(node):
            self.findings.append(
                IDORFinding(
                    path=self.path,
                    lineno=node.lineno,
                    pattern="unvalidated_id_lookup",
                    severity="high",
                    message="Object lookup uses request-controlled ID without ownership check",
                    function=self._current_function(),
                )
            )
        self.generic_visit(node)


class IDORAnalyzer:
    """Detect insecure direct object reference (IDOR) patterns in Python code."""

    def __init__(self, root: str, *, ignore_dirs: set[str] | None = None) -> None:
        self.root = Path(root)
        self.ignore_dirs = ignore_dirs or set(DEFAULT_IGNORE_DIRS)
        self._findings: list[IDORFinding] = []
        self._stats: IDORStats | None = None
        self._files_scanned = 0

    def _should_skip(self, path: Path) -> bool:
        if any(part in self.ignore_dirs for part in path.parts):
            return True
        return path.suffix != ".py"

    def _scan_line_patterns(self, rel: str, source: str) -> list[IDORFinding]:
        findings: list[IDORFinding] = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            for pattern in _LINE_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        IDORFinding(
                            path=rel,
                            lineno=lineno,
                            pattern="unvalidated_id_lookup",
                            severity="high",
                            message="Object lookup may use user-controlled ID without authorization",
                        )
                    )
                    break
        return findings

    def analyze(self) -> list[IDORFinding]:
        if self._findings:
            return self._findings

        findings: list[IDORFinding] = []
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
            visitor = _IDORVisitor(rel)
            visitor.visit(tree)
            line_findings = self._scan_line_patterns(rel, source)
            combined = visitor.findings + line_findings
            if combined:
                files_with_findings.add(rel)
            findings.extend(combined)

        self._findings = findings
        self._files_scanned = files_scanned
        by_pattern: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_pattern[finding.pattern] = by_pattern.get(finding.pattern, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        density = round(100.0 * len(findings) / files_scanned, 1) if files_scanned else 0.0
        self._stats = IDORStats(
            total_findings=len(findings),
            by_pattern=by_pattern,
            by_severity=by_severity,
            files_with_findings=len(files_with_findings),
            finding_density=density,
        )
        return findings

    @property
    def stats(self) -> IDORStats:
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
            f"IDOR risks: {stats.total_findings} findings in "
            f"{stats.files_with_findings} files ({self._files_scanned} scanned)\n"
            f"Health score: {self.health_score()}/100"
        )

    def to_context(self, limit: int = 30) -> str:
        self.analyze()
        lines = ["IDOR analysis:", self.summary(), "", "Findings:"]
        if not self._findings:
            lines.append("No IDOR risks found.")
        else:
            for finding in self._findings[:limit]:
                lines.append(finding.format())
        return "\n".join(lines)
